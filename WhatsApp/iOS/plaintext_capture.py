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


CAPTURE_HOST = "whatsapp-debug.invalid"
ACK_HEADER = "X-WA-ENC-Receiver"
DEFAULT_HOOK = Path(__file__).with_name("plaintext_hook.js")


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
            # Absolute-form request targets send the request through the HTTP proxy.
            connection.request(method, f"http://{CAPTURE_HOST}{path}", body=body, headers=headers or {})
            response = connection.getresponse()
            response.read()
            if response.status != 200 or response.getheader(ACK_HEADER) != "1":
                raise RuntimeError(
                    f"Receiver did not acknowledge the request (HTTP {response.status}). "
                    "Load WhatsApp/plaintext_mitmproxy.py and use --set connection_strategy=lazy."
                )
        finally:
            connection.close()

    def probe(self) -> None:
        self.request("GET", "/__health")

    def post(self, metadata: dict, plaintext: bytes) -> None:
        source = metadata.get("source", "query")
        original_url = metadata.get("original_url") or ""
        path = urlsplit(original_url).path if original_url else ""
        path = quote(path or f"/capture/{source}", safe="/%")
        if not path.startswith("/"):
            path = "/" + path
        encoded_metadata = base64.b64encode(
            json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
            if source == "query" else "application/octet-stream",
            "X-WA-Capture-Source": safe_header(source),
            "X-WA-Capture-Sequence": safe_header(metadata.get("sequence", "")),
            "X-WA-Capture-Metadata": encoded_metadata,
            "User-Agent": "wa-enc-collector/1.0",
        }
        if original_url:
            headers["X-WA-Original-URL"] = safe_header(original_url)
        self.request("POST", path, plaintext, headers)


class Collector:
    """Keep proxy I/O off Frida's message callback thread."""

    def __init__(self, sink: ProxySink, jsonl: str | None, stop: threading.Event):
        self.sink = sink
        self.stop = stop
        self.records: queue.Queue = queue.Queue(maxsize=1024)
        self.jsonl = Path(jsonl).expanduser().open("a", encoding="utf-8") if jsonl else None
        self.sent = self.errors = self.dropped = 0
        self.thread = threading.Thread(target=self.worker, name="wa-enc-forwarder", daemon=True)
        self.thread.start()

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
        if payload.get("kind") == "plaintext":
            try:
                self.records.put_nowait((dict(payload), bytes(data or b"")))
            except queue.Full:
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
                    print(
                        f"[capture {metadata.get('sequence')}] {metadata.get('source')}: "
                        f"{len(plaintext)} bytes sent to mitmproxy",
                        flush=True,
                    )
                except Exception as error:
                    self.errors += 1
                    print(f"[collector] Forwarding failed: {error}", file=sys.stderr, flush=True)
            finally:
                self.records.task_done()

    def close(self) -> None:
        # The caller detaches first, so no new Frida messages should be queued.
        # Keep all queued records, then ask the worker to stop.
        self.records.put(None)
        while self.thread.is_alive():
            self.thread.join(timeout=0.25)
        if self.jsonl is not None:
            self.jsonl.close()
        print(f"[collector] Forwarded: {self.sent}; errors: {self.errors}; dropped: {self.dropped}", flush=True)


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
    parser.add_argument("--bundle", default="net.whatsapp.WhatsApp", help="iOS bundle identifier to spawn")
    parser.add_argument("--attach", metavar="PID_OR_NAME", help="Attach to a running PID, name, or bundle instead of spawning")
    devices = parser.add_mutually_exclusive_group()
    devices.add_argument("--remote", metavar="HOST:PORT", help="Frida server address; default transport is USB")
    devices.add_argument("--device-id", help="Use a specific Frida device ID")
    parser.add_argument("--source", choices=("query", "aes", "both"), default="query", help="Hook to capture; default: ENC query serializer")
    parser.add_argument("--hook", type=Path, default=DEFAULT_HOOK, help="Frida JavaScript agent file")
    parser.add_argument("--jsonl", metavar="PATH", help="Also append metadata and exact plaintext to JSON Lines")
    parser.add_argument("--test", action="store_true", help="Send one sample capture and exit without requiring Frida/iOS")
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
            sample = b"test=1&message=hello%2Bworld&unicode=%C3%A1"
            collector.on_message({"type": "send", "payload": {
                "kind": "plaintext", "source": "query", "sequence": 1,
                "captured_at_ms": int(time.time() * 1000), "byte_length": len(sample),
                "original_url": "https://example.invalid/v2/test", "test": True,
            }}, sample)
        else:
            agent_source = args.hook.read_text(encoding="utf-8")
            if agent_source.count("__CONFIG__") != 1:
                raise ValueError(f"Agent file must contain one __CONFIG__ placeholder: {args.hook}")
            agent = agent_source.replace("__CONFIG__", json.dumps({"source": args.source}), 1)
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
                spawned_pid = device.spawn([args.bundle])
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
            print(f"[collector] Capturing PID {pid}; trigger the request in the app. Ctrl+C stops capture.", flush=True)
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
