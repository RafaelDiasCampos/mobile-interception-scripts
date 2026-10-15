from __future__ import annotations

import argparse
import base64
import http.client
import json
import queue
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit


DEBUG_HOST = "whatsapp-debug.invalid"
DEBUG_PATH = "/whatsapp/plaintext"
ACK_HEADER = "X-WA-Plaintext-Ack"
DEFAULT_HOOK = Path(__file__).with_name("plaintext_hook.js")
MAX_BODY_BYTES = 1024 * 1024
MAX_PENDING_CAPTURES = 64
MAX_PENDING_BYTES = 8 * 1024 * 1024


def proxy_address(value: str) -> tuple[str, int]:
    parsed = urlsplit(value if "://" in value else "http://" + value)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("--proxy must be an HTTP proxy, e.g. http://127.0.0.1:8080")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("--proxy must contain only the proxy host and port")
    return parsed.hostname, parsed.port or 8080


def safe_header(value: object) -> str:
    return str(value).replace("\r", "").replace("\n", "").encode("ascii", "backslashreplace").decode("ascii")


class ProxySink:
    def __init__(self, proxy: str, timeout: float = 5.0):
        self.host, self.port = proxy_address(proxy)
        self.timeout = timeout

    def request(self, method: str, path: str, body: bytes = b"", headers: dict | None = None) -> None:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            # Absolute-form targets make the synthetic request visible to mitmproxy.
            connection.putrequest(method, f"http://{DEBUG_HOST}{path}",
                                  skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", DEBUG_HOST)
            for name, value in (headers or {}).items():
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("Connection", "close")
            connection.endheaders(body)
            response = connection.getresponse()
            response.read()
            expected_status = 200 if method == "GET" else 204
            if response.status != expected_status or response.getheader(ACK_HEADER) != "1":
                raise RuntimeError(
                    f"Receiver did not acknowledge the request (HTTP {response.status}). "
                    "Load WhatsApp/plaintext_mitmproxy.py in mitmproxy."
                )
        finally:
            connection.close()

    def probe(self) -> None:
        self.request("GET", "/__health")

    def post(self, metadata: dict, plaintext: bytes) -> None:
        capture_id = str(metadata["capture_id"])
        path = DEBUG_PATH + "?capture=" + quote(capture_id, safe="-._~")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-WA-Frida-Debug": "plaintext-v1",
            "X-WA-Capture-Id": safe_header(capture_id),
            "X-WA-Capture-Time": safe_header(metadata["captured_at"]),
            "X-WA-Thread-Id": safe_header(metadata["thread_id"]),
            "X-WA-Hook": safe_header(metadata["hook"]),
            "X-WA-Build-Id": safe_header(metadata["build_id"]),
        }
        self.request("POST", path, plaintext, headers)


class Collector:
    """Keep proxy I/O off Frida's message callback thread."""

    def __init__(self, sink: ProxySink, jsonl: str | None, stop: threading.Event):
        self.sink = sink
        self.stop = stop
        self.records: queue.Queue = queue.Queue(maxsize=MAX_PENDING_CAPTURES)
        self.lock = threading.Lock()
        self.pending_count = 0
        self.pending_bytes = 0
        self.jsonl = Path(jsonl).expanduser().open("a", encoding="utf-8") if jsonl else None
        self.sent = self.errors = self.dropped = 0
        self.worker_thread = threading.Thread(target=self.worker, name="wa-android-forwarder", daemon=True)
        self.worker_thread.start()

    def on_message(self, message: dict, data: bytes | None) -> None:
        if message.get("type") == "error":
            print("[agent error] " + str(message.get("stack", message.get("description"))), file=sys.stderr)
            self.stop.set()
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        if payload.get("kind") == "status":
            print(f"[agent {payload.get('level')}] {payload.get('text')}", flush=True)
            if payload.get("level") == "fatal":
                self.stop.set()
            return
        if payload.get("kind") != "plaintext":
            return
        body = bytes(data or b"")
        if payload.get("byte_length") != len(body) or len(body) > MAX_BODY_BYTES:
            self.dropped += 1
            print("[collector] Invalid plaintext length; capture dropped.", file=sys.stderr, flush=True)
            return
        with self.lock:
            if (self.pending_count >= MAX_PENDING_CAPTURES or
                    self.pending_bytes + len(body) > MAX_PENDING_BYTES):
                self.dropped += 1
                print("[collector] Queue full; capture dropped.", file=sys.stderr, flush=True)
                return
            self.pending_count += 1
            self.pending_bytes += len(body)
            try:
                self.records.put_nowait((dict(payload), body))
            except queue.Full:
                self.pending_count -= 1
                self.pending_bytes -= len(body)
                self.dropped += 1
                print("[collector] Queue full; capture dropped.", file=sys.stderr, flush=True)

    def worker(self) -> None:
        while True:
            record = self.records.get()
            try:
                if record is None:
                    return
                metadata, plaintext = record
                if self.jsonl is not None:
                    try:
                        stored = dict(metadata, plaintext_base64=base64.b64encode(plaintext).decode("ascii"))
                        try:
                            stored["plaintext_utf8"] = plaintext.decode("utf-8")
                        except UnicodeDecodeError:
                            pass
                        self.jsonl.write(json.dumps(stored, ensure_ascii=False) + "\n")
                        self.jsonl.flush()
                    except Exception as error:
                        self.errors += 1
                        print(f"[collector] JSONL write failed: {error}", file=sys.stderr, flush=True)
                try:
                    self.sink.post(metadata, plaintext)
                    self.sent += 1
                    print(f"[capture {metadata.get('capture_id')}] {len(plaintext)} bytes sent to mitmproxy",
                          flush=True)
                except Exception as error:
                    self.errors += 1
                    print(f"[collector] Forwarding failed: {error}", file=sys.stderr, flush=True)
            finally:
                if record is not None:
                    with self.lock:
                        self.pending_count -= 1
                        self.pending_bytes -= len(record[1])
                self.records.task_done()

    def close(self) -> None:
        # Frida is detached before this call, so no new records should arrive.
        self.records.put(None)
        while self.worker_thread.is_alive():
            self.worker_thread.join(timeout=0.25)
        if self.jsonl is not None:
            self.jsonl.close()
        print(f"[collector] Forwarded: {self.sent}; errors: {self.errors}; dropped: {self.dropped}",
              flush=True)


def attach_pid(device, target: str) -> int:
    if target.isdecimal():
        return int(target)
    applications = [app for app in device.enumerate_applications() if app.identifier == target and app.pid]
    if len(applications) == 1:
        return applications[0].pid
    return device.get_process(target).pid


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="Regular HTTP mitmproxy listener")
    parser.add_argument("--package", default="com.whatsapp", help="Android package to spawn")
    parser.add_argument("--attach", metavar="PID_OR_NAME", help="Attach to a running PID or process name instead of spawning")
    devices = parser.add_mutually_exclusive_group()
    devices.add_argument("--remote", metavar="HOST:PORT", help="Frida server address; default transport is USB")
    devices.add_argument("--device-id", help="Use a specific Frida device ID")
    parser.add_argument("--hook", type=Path, default=DEFAULT_HOOK, help="Frida JavaScript agent file")
    parser.add_argument("--jsonl", metavar="PATH", help="Also append metadata and exact plaintext to JSON Lines")
    parser.add_argument("--test", action="store_true", help="Send one sample capture and exit without requiring Frida/Android")
    parser.add_argument("--timeout", type=float, default=5.0, help="Proxy HTTP timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    sink = ProxySink(args.proxy, args.timeout)
    sink.probe()
    print("[collector] mitmproxy receiver ready.", flush=True)
    stop = threading.Event()
    collector = Collector(sink, args.jsonl, stop)
    session = None
    script = None
    device = None
    spawned_pid = None
    resumed = False
    failed = False
    try:
        if args.test:
            sample = b"test=1&message=hello%2Bworld"
            collector.on_message({"type": "send", "payload": {
                "kind": "plaintext", "capture_id": "test-" + str(int(time.time() * 1000)),
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "thread_id": 0, "hook": "libwhatsapp.so+0x73d020",
                "build_id": "test", "byte_length": len(sample),
            }}, sample)
        else:
            agent = args.hook.read_text(encoding="utf-8")
            try:
                import frida
            except ImportError as error:
                raise RuntimeError("Install the collector dependency: python3 -m pip install frida") from error
            if args.remote:
                device = frida.get_device_manager().add_remote_device(args.remote)
            elif args.device_id:
                device = frida.get_device(args.device_id, timeout=5)
            else:
                device = frida.get_usb_device(timeout=5)
            if args.attach:
                pid = attach_pid(device, args.attach)
            else:
                spawned_pid = device.spawn([args.package])
                pid = spawned_pid
            session = device.attach(pid)

            def detached(reason, crash=None):
                print(f"[collector] Session detached: {reason}", flush=True)
                stop.set()

            session.on("detached", detached)
            script = session.create_script(agent)
            script.on("message", collector.on_message)
            script.load()
            if spawned_pid is not None:
                device.resume(spawned_pid)
                resumed = True
            print(f"[collector] Capturing PID {pid}; trigger the request in the app. Ctrl+C stops capture.",
                  flush=True)
            while not stop.wait(0.25):
                pass
            failed = True  # The loop ends on an agent error or an unexpected detach.
    except KeyboardInterrupt:
        print("\n[collector] Stopping...", flush=True)
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if spawned_pid is not None and not resumed:
            try:
                device.resume(spawned_pid)
            except Exception:
                pass
        collector.close()
    return 1 if failed or collector.errors or collector.dropped else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"[collector] {error}", file=sys.stderr)
        raise SystemExit(1)
