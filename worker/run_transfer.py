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
import re
import sys
import time
from typing import Any

from cryptography.fernet import Fernet
import httpx

# 32 MB RAM chunk size (128 * 256 KB — exact multiple of Google Drive's 256 KB requirement)
WORKER_RAM_CHUNK_BYTES = 32 * 1024 * 1024
# 5.5 hours safety window before GitHub Actions 6-hour hard timeout
DEFAULT_MAX_RUNTIME_SECONDS = int(os.getenv("MAX_WORKER_RUNTIME_SECONDS", str(5 * 3600 + 1800)))

GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
RANGE_HEADER_RE = re.compile(r"bytes=0-(\d+)", re.IGNORECASE)


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


def _run_worker_job_impl(
    encrypted_payload: str,
    secret_key: str,
    *,
    chunk_size: int = WORKER_RAM_CHUNK_BYTES,
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
                chunk_idx = (current_offset // chunk_size) + 1
                ram_buf = bytearray()
                completed_meta: dict[str, Any] | None = None
                initial_offset = current_offset
                stream_t0 = time.monotonic()

                for net_bytes in resp.iter_bytes(chunk_size=256 * 1024):
                    ram_buf.extend(net_bytes)

                    while len(ram_buf) >= chunk_size:
                        piece = bytes(ram_buf[:chunk_size])
                        del ram_buf[:chunk_size]

                        is_final = bool(
                            total_size is not None
                            and (current_offset + len(piece)) >= total_size
                        )
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
                        mb_per_s = (len(piece) / (1024.0 * 1024.0)) / dt
                        current_offset = new_offset
                        pct = (
                            (current_offset / total_size * 100.0)
                            if (total_size and total_size > 0)
                            else 0.0
                        )
                        # Zero-Knowledge redacted console output (no URL, no filename, no headers)
                        print(
                            f"Job #{job_id} | Chunk {chunk_idx}/{total_chunks} "
                            f"({pct:.1f}% - {format_bytes(current_offset)} / {format_bytes(total_size)}) "
                            f"@ {mb_per_s:.1f} MB/s",
                            flush=True,
                        )
                        chunk_idx += 1

                        if done_meta is not None:
                            completed_meta = done_meta

                        # Save encrypted progress checkpoint
                        write_encrypted_checkpoint(
                            secret_key,
                            {
                                "item_id": job_id,
                                "status": "STREAMING",
                                "bytes_transferred": current_offset,
                                "progress_pct": round(pct, 2),
                                "speed_bps": round(len(piece) / dt, 2),
                                "resumable_session_uri": session_uri,
                            },
                            path=checkpoint_path,
                        )

                        if reporter is not None:
                            elapsed = max(1.0, time.monotonic() - stream_t0)
                            avg_bps = (current_offset - initial_offset) / elapsed
                            remaining = (total_size - current_offset) if total_size else 0
                            reporter.send(
                                {
                                    "status": "STREAMING",
                                    "bytes_transferred": current_offset,
                                    "progress_pct": round(pct, 2),
                                    "speed_bps": round(avg_bps, 2),
                                    "eta_seconds": int(remaining / avg_bps) if avg_bps > 0 and remaining > 0 else 0,
                                    "size_bytes": total_size,
                                    "resumable_session_uri": session_uri,
                                }
                            )
                        if (time.monotonic() - worker_start) >= max_runtime_seconds and not is_final:
                            pause_state = {
                                "item_id": job_id,
                                "status": "PAUSED_WINDOW_LIMIT",
                                "bytes_transferred": current_offset,
                                "progress_pct": round(pct, 2),
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

                if len(ram_buf) > 0 and completed_meta is None:
                    piece = bytes(ram_buf)
                    ram_buf.clear()
                    if total_size is None:
                        total_size = current_offset + len(piece)
                    t0 = time.monotonic()
                    new_offset, done_meta = upload_chunk(
                        session_uri,
                        piece,
                        start_byte=current_offset,
                        total_size=total_size,
                        is_final=True,
                        client=drive_client,
                    )
                    dt = max(0.001, time.monotonic() - t0)
                    mb_per_s = (len(piece) / (1024.0 * 1024.0)) / dt
                    current_offset = new_offset
                    if done_meta is not None:
                        completed_meta = done_meta
                    print(
                        f"Job #{job_id} | Chunk {chunk_idx}/{total_chunks} "
                        f"(100.0% - {format_bytes(current_offset)} / {format_bytes(total_size)}) "
                        f"@ {mb_per_s:.1f} MB/s",
                        flush=True,
                    )

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
