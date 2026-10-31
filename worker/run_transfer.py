#!/usr/bin/env python3
"""Standalone GitHub Actions Cloud Worker for 100% Cloud-to-Cloud Google Drive Streaming.

Zero-Knowledge / Public-Repo Safe Design:
- Reads `WORKER_PAYLOAD_SECRET` and `ENCRYPTED_PAYLOAD` strictly from environment variables.
- Decrypts the transfer job payload in RAM using Fernet (AES-128-CBC + HMAC-SHA256).
- Streams directly from the source URL (`Range: bytes=...`) in 32 MB RAM chunks into
  Google Drive's Resumable Upload API (`PUT https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable`).
- Never prints URLs, filenames, custom headers, or tokens to console logs.
- Saves an encrypted checkpoint (`worker_result.enc`) with the Google Drive `resumable_session_uri`
  and `bytes_transferred` to support multi-part 6-hour window continuation and status polling.
"""

from __future__ import annotations

import json
import math
import os
import queue
import re
import sys
import threading
import time
from typing import Any

from cryptography.fernet import Fernet
import httpx

# Configurable RAM chunk size (default: 32 MB, multiple of Google Drive's 256 KB requirement)
_chunk_mb_env = os.getenv("WORKER_RAM_CHUNK_MB")
WORKER_RAM_CHUNK_BYTES = (
    max(1, int(_chunk_mb_env)) * 1024 * 1024
    if _chunk_mb_env and _chunk_mb_env.isdigit()
    else 32 * 1024 * 1024
)
# Configurable concurrent download streams for S3/OVH Range fetching (default: 1 for single-connection pipeline to avoid S3 tenant rate-limiting)
_concurrency_env = os.getenv("WORKER_CONCURRENCY")
DEFAULT_WORKER_CONCURRENCY = (
    max(1, min(8, int(_concurrency_env)))
    if _concurrency_env and _concurrency_env.isdigit()
    else 1
)
# 5.5 hours safety window before GitHub Actions 6-hour hard timeout
DEFAULT_MAX_RUNTIME_SECONDS = int(os.getenv("MAX_WORKER_RUNTIME_SECONDS", str(5 * 3600 + 1800)))

GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
RANGE_HEADER_RE = re.compile(r"bytes=0-(\d+)", re.IGNORECASE)


class RangeNotSupportedError(Exception):
    """Raised when source does not support multi-part range slicing."""


def format_bytes(num_bytes: int | None) -> str:
    if num_bytes is None or num_bytes < 0:
        return "Unknown"
    if num_bytes == 0:
        return "0.00 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(num_bytes)
    idx = 0
    while val >= 1024.0 and idx < len(units) - 1:
        val /= 1024.0
        idx += 1
    return f"{val:.2f} {units[idx]}"


def format_eta(sec: int | None) -> str:
    if sec is None or sec <= 0:
        return "--"
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    if h > 0:
        return f"{h}h {m}m"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def decrypt_payload(encrypted_payload: str, secret_key: str) -> dict[str, Any]:
    f = Fernet(secret_key.encode("utf-8"))
    raw = f.decrypt(encrypted_payload.encode("utf-8")).decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Invalid job payload structure.")
    return data


def write_encrypted_checkpoint(secret_key: str, state: dict[str, Any], path: str = "worker_result.enc") -> None:
    f = Fernet(secret_key.encode("utf-8"))
    raw = json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    token = f.encrypt(raw).decode("utf-8")
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(token)


class ProgressReporter:
    """Sends throttled, Fernet-encrypted progress updates to the app (zero-knowledge: no URL/filename).

    Failures are swallowed on purpose: a reporting hiccup must never interrupt a transfer.
    """

    def __init__(
        self,
        report_url: str | None,
        secret_key: str,
        item_id: int,
        min_interval: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.report_url = report_url
        self.secret_key = secret_key
        self.item_id = item_id
        self.min_interval = min_interval
        self.transport = transport
        self._last = 0.0

    def send(self, state: dict[str, Any], force: bool = False) -> None:
        if not self.report_url:
            return
        now = time.monotonic()
        if not force and (now - self._last) < self.min_interval:
            return
        self._last = now
        try:
            body = dict(state)
            body["item_id"] = self.item_id
            token = Fernet(self.secret_key.encode("utf-8")).encrypt(
                json.dumps(body, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            kwargs: dict[str, Any] = {"timeout": 10.0}
            if self.transport is not None:
                kwargs["transport"] = self.transport
            with httpx.Client(**kwargs) as client:
                client.post(self.report_url, json={"token": token})
        except Exception:
            pass


def ensure_access_token(token_bundle: dict[str, Any]) -> str:
    access_token = token_bundle.get("access_token", "")
    refresh_token = token_bundle.get("refresh_token", "")
    client_id = token_bundle.get("client_id", "")
    client_secret = token_bundle.get("client_secret", "")

    if refresh_token and client_id and client_secret:
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    token_bundle.get("token_uri", GOOGLE_TOKEN_ENDPOINT),
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()["access_token"]
        except Exception:
            pass

    if not access_token:
        raise RuntimeError("No valid Google Drive access token available in worker payload.")
    return access_token


def initiate_resumable_session(
    access_token: str,
    filename: str,
    folder_id: str,
    total_size: int | None,
    client: httpx.Client,
) -> str:
    metadata: dict[str, Any] = {"name": filename}
    if folder_id and folder_id != "root":
        metadata["parents"] = [folder_id]

    headers: dict[str, str] = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; charset=UTF-8",
        "X-Upload-Content-Type": "application/octet-stream",
    }
    if total_size is not None and total_size > 0:
        headers["X-Upload-Content-Length"] = str(total_size)

    resp = client.post(
        GOOGLE_DRIVE_UPLOAD_API,
        params={
            "uploadType": "resumable",
            "supportsAllDrives": "true",
            "fields": "id,name,size,webViewLink",
        },
        headers=headers,
        json=metadata,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Drive session init failed with HTTP {resp.status_code}.")
    loc = resp.headers.get("Location") or resp.headers.get("location")
    if not loc:
        raise RuntimeError("Drive session init missing Location header.")
    return loc


def query_session_offset(
    session_uri: str, total_size: int | None, client: httpx.Client
) -> tuple[int, dict[str, Any] | None]:
    total_str = str(total_size) if (total_size is not None and total_size > 0) else "*"
    resp = client.put(
        session_uri,
        headers={"Content-Length": "0", "Content-Range": f"bytes */{total_str}"},
    )
    if resp.status_code in (200, 201):
        return (total_size or 0), (resp.json() if resp.content else {})
    if resp.status_code == 308:
        rng = resp.headers.get("Range") or resp.headers.get("range") or ""
        m = RANGE_HEADER_RE.search(rng)
        if m:
            return int(m.group(1)) + 1, None
        return 0, None
    raise RuntimeError(f"Session offset query returned HTTP {resp.status_code}.")


def upload_chunk(
    session_uri: str,
    chunk_bytes: bytes,
    start_byte: int,
    total_size: int | None,
    is_final: bool,
    client: httpx.Client,
) -> tuple[int, dict[str, Any] | None]:
    chunk_len = len(chunk_bytes)
    end_byte = start_byte + chunk_len - 1
    if total_size is not None and total_size > 0:
        total_str = str(total_size)
    elif is_final:
        total_str = str(end_byte + 1)
    else:
        total_str = "*"

    headers = {
        "Content-Length": str(chunk_len),
        "Content-Range": f"bytes {start_byte}-{end_byte}/{total_str}",
    }
    resp = client.put(session_uri, content=chunk_bytes, headers=headers)
    if resp.status_code in (200, 201):
        return end_byte + 1, (resp.json() if resp.content else {})
    if resp.status_code == 308:
        rng = resp.headers.get("Range") or resp.headers.get("range") or ""
        m = RANGE_HEADER_RE.search(rng)
        if m:
            return int(m.group(1)) + 1, None
        return end_byte + 1, None
    raise RuntimeError(f"Chunk upload failed at offset {start_byte} with HTTP {resp.status_code}.")


def _check_source_slices_ranges(
    raw_url: str,
    headers: dict[str, str],
    src_kwargs: dict[str, Any],
    total_size: int,
) -> bool:
    """Send a tiny 1-byte range test at offset 1 to verify server actually slices ranges."""
    if total_size <= 1:
        return False
    try:
        test_hdrs = dict(headers)
        test_hdrs["Range"] = "bytes=1-1"
        with httpx.Client(**src_kwargs) as test_client:
            with test_client.stream("GET", raw_url, headers=test_hdrs) as resp:
                if resp.status_code != 206:
                    return False
                cr = resp.headers.get("Content-Range") or ""
                if cr.lower().startswith("bytes 0-"):
                    return False
                return True
    except Exception:
        return False


def _stream_multi_connection_ranges(
    job_id: int,
    raw_url: str,
    custom_headers: dict[str, str],
    session_uri: str,
    current_offset: int,
    total_size: int,
    chunk_size: int,
    concurrency: int,
    drive_client: httpx.Client,
    src_kwargs: dict[str, Any],
    secret_key: str,
    checkpoint_path: str,
    worker_start: float,
    max_runtime_seconds: int,
    reporter: ProgressReporter | None,
) -> dict[str, Any]:
    """Stage 2: Concurrent multi-connection range streaming pipeline with bounded RAM queue."""
    chunks_to_transfer: list[tuple[int, int, int, bool]] = []
    offset = current_offset
    idx = (current_offset // chunk_size) + 1
    total_chunks = max(1, math.ceil(total_size / chunk_size))

    while offset < total_size:
        end_b = min(offset + chunk_size, total_size)
        is_fin = bool(end_b >= total_size)
        chunks_to_transfer.append((idx, offset, end_b, is_fin))
        offset = end_b
        idx += 1

    if not chunks_to_transfer:
        return {
            "item_id": job_id,
            "status": "COMPLETED",
            "bytes_transferred": current_offset,
            "progress_pct": 100.0,
            "resumable_session_uri": None,
        }

    actual_concurrency = min(concurrency, len(chunks_to_transfer))
    max_buffered = actual_concurrency + 1

    download_queue: queue.Queue[tuple[int, int, int, bool]] = queue.Queue()
    for c in chunks_to_transfer:
        download_queue.put(c)

    ready_chunks: dict[int, tuple[bytes, float]] = {}
    condition = threading.Condition()
    stop_event = threading.Event()
    error_holder: list[Exception] = []

    def download_worker() -> None:
        with httpx.Client(**src_kwargs) as client:
            while not stop_event.is_set():
                with condition:
                    while len(ready_chunks) >= max_buffered and not stop_event.is_set():
                        condition.wait(timeout=0.2)
                if stop_event.is_set():
                    break

                try:
                    chunk_idx, start_b, end_b, is_fin = download_queue.get_nowait()
                except queue.Empty:
                    break

                try:
                    hdrs = dict(custom_headers)
                    hdrs["Range"] = f"bytes={start_b}-{end_b - 1}"
                    t0 = time.monotonic()
                    with client.stream("GET", raw_url, headers=hdrs) as resp:
                        if resp.status_code in (401, 403):
                            raise RuntimeError(
                                f"Source returned HTTP {resp.status_code} (Signature Expired)."
                            )
                        if resp.status_code not in (200, 206):
                            raise RuntimeError(f"Source returned HTTP {resp.status_code}.")
                        if resp.status_code == 200 and start_b > 0:
                            raise RangeNotSupportedError(
                                "Server returned HTTP 200 instead of 206 for Range request."
                            )
                        cr = resp.headers.get("Content-Range") or ""
                        if start_b > 0 and cr.lower().startswith("bytes 0-"):
                            raise RangeNotSupportedError(
                                f"Server ignored Range header; returned '{cr}' for offset {start_b}."
                            )

                        buf = bytearray()
                        target_len = end_b - start_b
                        for net_bytes in resp.iter_bytes(chunk_size=1024 * 1024):
                            if stop_event.is_set():
                                return
                            buf.extend(net_bytes)
                            if len(buf) >= target_len:
                                buf = buf[:target_len]
                                break

                        if len(buf) < target_len:
                            raise RuntimeError(
                                f"Premature EOF: expected {target_len} bytes for chunk {chunk_idx}, got {len(buf)}"
                            )

                    dt = max(0.001, time.monotonic() - t0)
                    dl_mb_s = (len(buf) / (1024.0 * 1024.0)) / dt

                    with condition:
                        ready_chunks[chunk_idx] = (bytes(buf), dl_mb_s)
                        condition.notify_all()

                    download_queue.task_done()
                except Exception as exc:
                    with condition:
                        if not error_holder:
                            error_holder.append(exc)
                        stop_event.set()
                        condition.notify_all()
                    break

    threads = [
        threading.Thread(target=download_worker, daemon=True)
        for _ in range(actual_concurrency)
    ]
    for t in threads:
        t.start()

    initial_offset = current_offset
    stream_t0 = time.monotonic()
    completed_meta: dict[str, Any] | None = None

    try:
        for chunk_idx, start_b, end_b, is_final in chunks_to_transfer:
            if (time.monotonic() - worker_start) >= max_runtime_seconds and not is_final:
                stop_event.set()
                with condition:
                    condition.notify_all()
                pause_state = {
                    "item_id": job_id,
                    "status": "PAUSED_WINDOW_LIMIT",
                    "bytes_transferred": current_offset,
                    "progress_pct": round(
                        (current_offset / total_size * 100.0) if total_size else 0.0, 2
                    ),
                    "resumable_session_uri": session_uri,
                    "message": "Reached 6-hour worker window; session saved for seamless continuation.",
                }
                write_encrypted_checkpoint(secret_key, pause_state, path=checkpoint_path)
                if reporter is not None:
                    reporter.send(pause_state, force=True)
                print(
                    f"Job #{job_id} | Reached 6h window at {format_bytes(current_offset)}; "
                    "resumable session saved.",
                    flush=True,
                )
                return pause_state

            with condition:
                while chunk_idx not in ready_chunks and not stop_event.is_set():
                    condition.wait(timeout=0.5)

                if stop_event.is_set() and chunk_idx not in ready_chunks:
                    if error_holder:
                        raise error_holder[0]
                    raise RuntimeError("Transfer interrupted.")

                piece, dl_mb_s = ready_chunks.pop(chunk_idx)
                condition.notify_all()

            t0 = time.monotonic()
            new_offset, done_meta = upload_chunk(
                session_uri,
                piece,
                start_byte=current_offset,
                total_size=total_size,
                is_final=is_final,
                client=drive_client,
            )
            dt = max(0.001, time.monotonic() - t0)
            drive_ul_mb_s = (len(piece) / (1024.0 * 1024.0)) / dt
            current_offset = new_offset
            if done_meta is not None:
                completed_meta = done_meta

            pct = (current_offset / total_size * 100.0) if (total_size and total_size > 0) else 0.0
            elapsed = max(1.0, time.monotonic() - stream_t0)
            avg_bps = (current_offset - initial_offset) / elapsed
            overall_mb_s = avg_bps / (1024.0 * 1024.0)
            remaining = (total_size - current_offset) if total_size else 0
            eta_seconds = int(remaining / avg_bps) if avg_bps > 0 and remaining > 0 else 0
            eta_str = format_eta(eta_seconds)

            print(
                f"Job #{job_id} | Chunk {chunk_idx}/{total_chunks} "
                f"({pct:.1f}% - {format_bytes(current_offset)} / {format_bytes(total_size)}) "
                f"@ {overall_mb_s:.1f} MB/s [DL: {dl_mb_s:.1f} MB/s | Drive: {drive_ul_mb_s:.1f} MB/s] "
                f"| ETA {eta_str}",
                flush=True,
            )

            write_encrypted_checkpoint(
                secret_key,
                {
                    "item_id": job_id,
                    "status": "STREAMING",
                    "bytes_transferred": current_offset,
                    "progress_pct": round(pct, 2),
                    "speed_bps": round(avg_bps, 2),
                    "eta_seconds": eta_seconds,
                    "resumable_session_uri": session_uri,
                },
                path=checkpoint_path,
            )

            if reporter is not None:
                reporter.send(
                    {
                        "status": "STREAMING",
                        "bytes_transferred": current_offset,
                        "progress_pct": round(pct, 2),
                        "speed_bps": round(avg_bps, 2),
                        "eta_seconds": eta_seconds,
                        "size_bytes": total_size,
                        "resumable_session_uri": session_uri,
                    }
                )
    finally:
        stop_event.set()
        with condition:
            condition.notify_all()
        for t in threads:
            t.join(timeout=1.0)

    file_id = (completed_meta or {}).get("id") or f"gdrive_{job_id}"
    web_link = (completed_meta or {}).get("webViewLink") or (
        f"https://drive.google.com/file/d/{file_id}/view"
    )
    final_result = {
        "item_id": job_id,
        "status": "COMPLETED",
        "bytes_transferred": current_offset,
        "progress_pct": 100.0,
        "drive_file_id": file_id,
        "drive_web_link": web_link,
        "resumable_session_uri": None,
    }
    write_encrypted_checkpoint(secret_key, final_result, path=checkpoint_path)
    if reporter is not None:
        reporter.send(final_result, force=True)
    print(
        f"Job #{job_id} | Transfer Completed (100.0% - {format_bytes(current_offset)})", flush=True
    )
    return final_result


def _run_worker_job_impl(
    encrypted_payload: str,
    secret_key: str,
    *,
    chunk_size: int = WORKER_RAM_CHUNK_BYTES,
    concurrency: int = DEFAULT_WORKER_CONCURRENCY,
    max_runtime_seconds: int = DEFAULT_MAX_RUNTIME_SECONDS,
    source_transport: httpx.BaseTransport | None = None,
    drive_transport: httpx.BaseTransport | None = None,
    checkpoint_path: str = "worker_result.enc",
    reporter: ProgressReporter | None = None,
) -> dict[str, Any]:
    """Execute the cloud-to-cloud streaming job in RAM and return the final status dictionary."""
    worker_start = time.monotonic()
    payload = decrypt_payload(encrypted_payload, secret_key)

    job_id = int(payload.get("item_id") or payload.get("job_id") or 1)
    raw_url: str = payload["raw_url"]
    custom_headers: dict[str, str] = dict(payload.get("headers") or {})
    filename: str = payload["filename"]
    total_size: int | None = payload.get("size_bytes")
    folder_id: str = payload.get("drive_folder_id") or "root"
    token_bundle: dict[str, Any] = payload.get("google_token_bundle") or {}
    session_uri: str | None = payload.get("resumable_session_uri")

    drive_kwargs: dict[str, Any] = {"timeout": httpx.Timeout(120.0, connect=20.0)}
    if drive_transport is not None:
        drive_kwargs["transport"] = drive_transport

    src_kwargs: dict[str, Any] = {
        "follow_redirects": True,
        "timeout": httpx.Timeout(120.0, connect=20.0),
    }
    if source_transport is not None:
        src_kwargs["transport"] = source_transport

    access_token = ensure_access_token(token_bundle)
    current_offset = int(payload.get("bytes_transferred") or 0)

    with httpx.Client(**drive_kwargs) as drive_client:
        if session_uri:
            try:
                recovered_offset, done_meta = query_session_offset(
                    session_uri, total_size, drive_client
                )
                if done_meta is not None:
                    result = {
                        "item_id": job_id,
                        "status": "COMPLETED",
                        "bytes_transferred": total_size or recovered_offset,
                        "progress_pct": 100.0,
                        "drive_file_id": done_meta.get("id", ""),
                        "drive_web_link": done_meta.get("webViewLink", ""),
                        "resumable_session_uri": None,
                    }
                    write_encrypted_checkpoint(secret_key, result, path=checkpoint_path)
                    print(f"Job #{job_id} | Already completed (100.0%)")
                    return result
                current_offset = recovered_offset
            except Exception:
                session_uri = None
                current_offset = 0

        if not session_uri:
            session_uri = initiate_resumable_session(
                access_token, filename, folder_id, total_size, drive_client
            )
            current_offset = 0

        req_headers = dict(custom_headers)
        if current_offset > 0:
            req_headers["Range"] = f"bytes={current_offset}-"

        if reporter is not None:
            reporter.send(
                {
                    "status": "STREAMING",
                    "bytes_transferred": current_offset,
                    "progress_pct": round(current_offset / total_size * 100.0, 2)
                    if (total_size and total_size > 0)
                    else 0.0,
                    "size_bytes": total_size,
                    "resumable_session_uri": session_uri,
                },
                force=True,
            )

        if total_size is None:
            try:
                probe_headers = dict(custom_headers)
                probe_headers["Range"] = "bytes=0-0"
                with httpx.Client(**src_kwargs) as probe_client:
                    with probe_client.stream("GET", raw_url, headers=probe_headers) as probe_resp:
                        cr = probe_resp.headers.get("Content-Range")
                        if cr:
                            m_cr = re.search(r"/(\d+)", cr)
                            if m_cr:
                                total_size = int(m_cr.group(1))
                        if total_size is None and probe_resp.status_code == 200:
                            cl = probe_resp.headers.get("Content-Length")
                            if cl and cl.isdigit():
                                total_size = int(cl)
            except Exception:
                pass

        can_use_range = (
            concurrency > 1
            and total_size is not None
            and (total_size - current_offset) > chunk_size
            and _check_source_slices_ranges(raw_url, custom_headers, src_kwargs, total_size)
        )
        if can_use_range:
            try:
                print(
                    f"Job #{job_id} | Engaging Stage 2 Multi-Connection Range Pipeline "
                    f"({concurrency} parallel streams, {max(1, chunk_size // (1024*1024))} MB chunks)...",
                    flush=True,
                )
                return _stream_multi_connection_ranges(
                    job_id=job_id,
                    raw_url=raw_url,
                    custom_headers=custom_headers,
                    session_uri=session_uri,
                    current_offset=current_offset,
                    total_size=total_size,
                    chunk_size=chunk_size,
                    concurrency=concurrency,
                    drive_client=drive_client,
                    src_kwargs=src_kwargs,
                    secret_key=secret_key,
                    checkpoint_path=checkpoint_path,
                    worker_start=worker_start,
                    max_runtime_seconds=max_runtime_seconds,
                    reporter=reporter,
                )
            except RangeNotSupportedError:
                print(
                    f"Job #{job_id} | Source does not support Range slicing; falling back to sequential stream.",
                    flush=True,
                )

        with httpx.Client(**src_kwargs) as src_client:
            with src_client.stream("GET", raw_url, headers=req_headers) as resp:
                if resp.status_code in (401, 403):
                    err_state = {
                        "item_id": job_id,
                        "status": "FAILED",
                        "bytes_transferred": current_offset,
                        "resumable_session_uri": session_uri,
                        "error_message": f"Source returned HTTP {resp.status_code} (Signature Expired).",
                    }
                    write_encrypted_checkpoint(secret_key, err_state, path=checkpoint_path)
                    if reporter is not None:
                        reporter.send(err_state, force=True)
                    print(f"Job #{job_id} | Failed: Source returned HTTP {resp.status_code}")
                    return err_state

                if resp.status_code not in (200, 206):
                    err_state = {
                        "item_id": job_id,
                        "status": "FAILED",
                        "bytes_transferred": current_offset,
                        "resumable_session_uri": session_uri,
                        "error_message": f"Source returned HTTP {resp.status_code}.",
                    }
                    write_encrypted_checkpoint(secret_key, err_state, path=checkpoint_path)
                    if reporter is not None:
                        reporter.send(err_state, force=True)
                    return err_state

                if total_size is None:
                    cl = resp.headers.get("Content-Length")
                    if cl and cl.isdigit():
                        total_size = current_offset + int(cl)

                total_chunks = (
                    max(1, math.ceil(total_size / chunk_size)) if total_size else 1
                )
                completed_meta: dict[str, Any] | None = None
                initial_offset = current_offset
                stream_t0 = time.monotonic()

                pipe_queue: queue.Queue[tuple[int, bytes, float, bool] | None] = queue.Queue(maxsize=2)
                producer_error: list[Exception] = []
                stop_event = threading.Event()

                def producer() -> None:
                    try:
                        ram_buf = bytearray()
                        cur_idx = (current_offset // chunk_size) + 1
                        cur_off = current_offset
                        chunk_dl_t0 = time.monotonic()

                        for net_bytes in resp.iter_bytes(chunk_size=1024 * 1024):
                            if stop_event.is_set():
                                return
                            ram_buf.extend(net_bytes)

                            while len(ram_buf) >= chunk_size:
                                piece = bytes(ram_buf[:chunk_size])
                                del ram_buf[:chunk_size]
                                dl_dt = max(0.001, time.monotonic() - chunk_dl_t0)
                                dl_mb_s = (len(piece) / (1024.0 * 1024.0)) / dl_dt
                                is_fin = bool(
                                    total_size is not None
                                    and (cur_off + len(piece)) >= total_size
                                )
                                cur_off += len(piece)
                                pipe_queue.put((cur_idx, piece, dl_mb_s, is_fin))
                                cur_idx += 1
                                chunk_dl_t0 = time.monotonic()

                        if len(ram_buf) > 0 and not stop_event.is_set():
                            piece = bytes(ram_buf)
                            ram_buf.clear()
                            dl_dt = max(0.001, time.monotonic() - chunk_dl_t0)
                            dl_mb_s = (len(piece) / (1024.0 * 1024.0)) / dl_dt
                            pipe_queue.put((cur_idx, piece, dl_mb_s, True))
                    except Exception as exc:
                        producer_error.append(exc)
                    finally:
                        pipe_queue.put(None)

                producer_thread = threading.Thread(
                    target=producer, name="CDM-Stream-Producer", daemon=True
                )
                producer_thread.start()

                try:
                    while True:
                        if (time.monotonic() - worker_start) >= max_runtime_seconds:
                            stop_event.set()
                            pause_state = {
                                "item_id": job_id,
                                "status": "PAUSED_WINDOW_LIMIT",
                                "bytes_transferred": current_offset,
                                "progress_pct": round(
                                    (current_offset / total_size * 100.0) if total_size else 0.0, 2
                                ),
                                "resumable_session_uri": session_uri,
                                "message": "Reached 6-hour worker window; session saved for seamless continuation.",
                            }
                            write_encrypted_checkpoint(secret_key, pause_state, path=checkpoint_path)
                            if reporter is not None:
                                reporter.send(pause_state, force=True)
                            print(
                                f"Job #{job_id} | Reached 6h window at {format_bytes(current_offset)}; "
                                "resumable session saved.",
                                flush=True,
                            )
                            return pause_state

                        item = pipe_queue.get()
                        if item is None:
                            if producer_error:
                                raise producer_error[0]
                            break

                        chunk_idx, piece, dl_mb_s, is_final = item

                        t0 = time.monotonic()
                        new_offset, done_meta = upload_chunk(
                            session_uri,
                            piece,
                            start_byte=current_offset,
                            total_size=total_size,
                            is_final=is_final,
                            client=drive_client,
                        )
                        dt = max(0.001, time.monotonic() - t0)
                        drive_ul_mb_s = (len(piece) / (1024.0 * 1024.0)) / dt
                        current_offset = new_offset

                        if done_meta is not None:
                            completed_meta = done_meta

                        pct = (
                            (current_offset / total_size * 100.0)
                            if (total_size and total_size > 0)
                            else 0.0
                        )
                        elapsed = max(1.0, time.monotonic() - stream_t0)
                        avg_bps = (current_offset - initial_offset) / elapsed
                        overall_mb_s = avg_bps / (1024.0 * 1024.0)
                        remaining = (total_size - current_offset) if total_size else 0
                        eta_seconds = int(remaining / avg_bps) if avg_bps > 0 and remaining > 0 else 0
                        eta_str = format_eta(eta_seconds)

                        print(
                            f"Job #{job_id} | Chunk {chunk_idx}/{total_chunks} "
                            f"({pct:.1f}% - {format_bytes(current_offset)} / {format_bytes(total_size)}) "
                            f"@ {overall_mb_s:.1f} MB/s [DL: {dl_mb_s:.1f} MB/s | Drive: {drive_ul_mb_s:.1f} MB/s] "
                            f"| ETA {eta_str}",
                            flush=True,
                        )

                        write_encrypted_checkpoint(
                            secret_key,
                            {
                                "item_id": job_id,
                                "status": "STREAMING",
                                "bytes_transferred": current_offset,
                                "progress_pct": round(pct, 2),
                                "speed_bps": round(avg_bps, 2),
                                "eta_seconds": eta_seconds,
                                "resumable_session_uri": session_uri,
                            },
                            path=checkpoint_path,
                        )

                        if reporter is not None:
                            reporter.send(
                                {
                                    "status": "STREAMING",
                                    "bytes_transferred": current_offset,
                                    "progress_pct": round(pct, 2),
                                    "speed_bps": round(avg_bps, 2),
                                    "eta_seconds": eta_seconds,
                                    "size_bytes": total_size,
                                    "resumable_session_uri": session_uri,
                                }
                            )
                finally:
                    stop_event.set()
                    producer_thread.join(timeout=1.0)

        file_id = (completed_meta or {}).get("id") or f"gdrive_{job_id}"
        web_link = (completed_meta or {}).get("webViewLink") or (
            f"https://drive.google.com/file/d/{file_id}/view"
        )
        final_result = {
            "item_id": job_id,
            "status": "COMPLETED",
            "bytes_transferred": current_offset,
            "progress_pct": 100.0,
            "drive_file_id": file_id,
            "drive_web_link": web_link,
            "resumable_session_uri": None,
        }
        write_encrypted_checkpoint(secret_key, final_result, path=checkpoint_path)
        if reporter is not None:
            reporter.send(final_result, force=True)
        print(f"Job #{job_id} | Transfer Completed (100.0% - {format_bytes(current_offset)})", flush=True)
        return final_result


def run_worker_job(
    encrypted_payload: str,
    secret_key: str,
    *,
    chunk_size: int = WORKER_RAM_CHUNK_BYTES,
    concurrency: int = DEFAULT_WORKER_CONCURRENCY,
    max_runtime_seconds: int = DEFAULT_MAX_RUNTIME_SECONDS,
    source_transport: httpx.BaseTransport | None = None,
    drive_transport: httpx.BaseTransport | None = None,
    checkpoint_path: str = "worker_result.enc",
    report_url: str | None = None,
) -> dict[str, Any]:
    """Execute the cloud-to-cloud streaming job in RAM with live encrypted progress callbacks."""
    payload = decrypt_payload(encrypted_payload, secret_key)
    resolved_report_url = report_url or payload.get("report_url") or os.getenv("APP_REPORT_URL")
    job_id = int(payload.get("item_id") or payload.get("job_id") or 1)
    reporter = (
        ProgressReporter(
            resolved_report_url,
            secret_key,
            item_id=job_id,
            transport=drive_transport,
        )
        if resolved_report_url
        else None
    )

    try:
        res = _run_worker_job_impl(
            encrypted_payload,
            secret_key,
            chunk_size=chunk_size,
            concurrency=concurrency,
            max_runtime_seconds=max_runtime_seconds,
            source_transport=source_transport,
            drive_transport=drive_transport,
            checkpoint_path=checkpoint_path,
            reporter=reporter,
        )
        if reporter is not None:
            reporter.send(res, force=True)
        return res
    except Exception as exc:
        if reporter is not None:
            reporter.send(
                {
                    "item_id": job_id,
                    "status": "FAILED",
                    "error_message": f"Worker execution error: {type(exc).__name__}",
                },
                force=True,
            )
        raise


def main() -> int:
    secret_key = os.getenv("WORKER_PAYLOAD_SECRET", "").strip()
    encrypted_payload = os.getenv("ENCRYPTED_PAYLOAD", "").strip()
    if not secret_key or not encrypted_payload:
        print("Error: Missing required encrypted environment variables.", file=sys.stderr)
        return 1

    try:
        res = run_worker_job(encrypted_payload, secret_key)
        return 0 if res.get("status") in ("COMPLETED", "PAUSED_WINDOW_LIMIT") else 2
    except Exception as exc:
        # Never print raw exception message if it might contain URLs; print only class name
        print(f"Worker execution error ({type(exc).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
