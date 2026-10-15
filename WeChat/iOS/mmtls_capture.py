from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import json
import math
from pathlib import Path
import queue
import struct
import sys
import threading
from urllib.parse import urlsplit

CAPTURE_URL = "http://capture.invalid/__frida_wechat_ios_request"
MAX_BODY_BYTES = 16 * 1024 * 1024
WIRE_PREVIEW_BYTES = 256 * 1024


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("varint exceeds 64 bits")
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset
    raise ValueError("invalid varint")


def _wire_fields(data: bytes, depth: int = 0, budget: list[int] | None = None) -> list[dict]:
    """Schema-free preview. Length-delimited nested messages are only guesses."""
    budget = [512] if budget is None else budget
    fields = []
    offset = 0
    while offset < len(data):
        if budget[0] <= 0:
            raise ValueError("field preview limit exceeded")
        budget[0] -= 1
        tag, offset = _varint(data, offset)
        number, wire_type = tag >> 3, tag & 7
        if number == 0 or number >= 1 << 29:
            raise ValueError("invalid protobuf field number")
        field = {"field": number, "wire_type": wire_type}
        if wire_type == 0:
            value, offset = _varint(data, offset)
            # A schema is required to distinguish int/sint/enum/bool values.
            field["unsigned_varint"] = value
        elif wire_type in (1, 5):
            size = 8 if wire_type == 1 else 4
            if offset + size > len(data):
                raise ValueError("truncated fixed-width field")
            raw = data[offset:offset + size]
            offset += size
            field["unsigned_fixed"] = int.from_bytes(raw, "little")
            floating = struct.unpack("<d" if size == 8 else "<f", raw)[0]
            if math.isfinite(floating):
                field["possible_float"] = floating
        elif wire_type == 2:
            size, offset = _varint(data, offset)
            if offset + size > len(data):
                raise ValueError("truncated length-delimited field")
            raw = data[offset:offset + size]
            offset += size
            field["byte_length"] = size
            preview = raw[:512]
            field["hex_preview"] = preview.hex()
            if size > len(preview):
                field["preview_truncated"] = True
            try:
                text = raw[:2048].decode("utf-8")
                if text and all(c.isprintable() or c in "\n\r\t" for c in text):
                    field["utf8_preview"] = text
                    if size > 2048:
                        field["preview_truncated"] = True
            except UnicodeDecodeError:
                pass
            if raw and depth < 4 and size <= 8192 and "utf8_preview" not in field:
                remaining = budget[0]
                try:
                    field["possible_message"] = _wire_fields(raw, depth + 1, budget)
                except ValueError:
                    budget[0] = remaining
        else:
            raise ValueError("unsupported wire type (groups require a schema-aware decoder)")
        fields.append(field)
    return fields


def plaintext_view(body: bytes) -> dict:
    result = {"byte_length": len(body), "schema": None}
    if len(body) > WIRE_PREVIEW_BYTES:
        result.update(format="bytes", note="Wire preview omitted for a large request", hex_preview=body[:512].hex())
        return result
    try:
        result.update(format="protobuf-wire", fields=_wire_fields(body))
        result["note"] = "Field numbers only; nested messages and float interpretations are guesses."
    except ValueError as error:
        result.update(format="bytes", note=str(error), hex_preview=body[:512].hex())
        try:
            text = body[:4096].decode("utf-8")
            if all(c.isprintable() or c in "\n\r\t" for c in text):
                result["utf8_preview"] = text
        except UnicodeDecodeError:
            pass
    return result


def binary_view(body: bytes, note: str | None = None) -> dict:
    result = {
        "byte_length": len(body), "schema": None, "format": "bytes",
        "hex_preview": body[:512].hex(),
        "preview_truncated": len(body) > 512,
    }
    if note:
        result["note"] = note
    try:
        text = body[:4096].decode("utf-8")
        if text and all(c.isprintable() or c in "\n\r\t" for c in text):
            result["utf8_preview"] = text
            if len(body) > 4096:
                result["preview_truncated"] = True
    except UnicodeDecodeError:
        pass
    return result


def request_record(payload: dict, data: bytes | None, max_bytes: int) -> dict:
    if payload.get("type") != "request" or payload.get("schema_version") != 1:
        raise ValueError("expected request event schema_version=1")
    size = payload.get("body_length")
    if type(size) is not int or not 0 <= size <= max_bytes:
        raise ValueError("invalid or oversized request length")
    if data is None and size:
        raise ValueError("Frida event is missing binary request data")
    body = bytes(data or b"")
    if len(body) != size:
        raise ValueError("Frida body_length does not match binary request data")
    content_type = payload.get("request_content_type", "application/x-protobuf")
    if content_type not in ("application/x-protobuf", "application/octet-stream"):
        raise ValueError("unsupported captured request content type")
    # Only request metadata is accepted. A response event is never forwarded.
    record = dict(payload)
    record["request_content_type"] = content_type
    record["request_body_b64"] = base64.b64encode(body).decode("ascii")
    if content_type == "application/x-protobuf":
        record["request_view"] = plaintext_view(body)
    else:
        record["request_view"] = binary_view(body, payload.get("request_semantics"))
    return record


class ProxyForwarder:
    """A bounded background queue keeps network I/O out of Frida callbacks."""

    def __init__(self, proxy_url: str, queue_size: int = 256, timeout: float = 3.0):
        proxy = urlsplit(proxy_url)
        if (proxy.scheme != "http" or not proxy.hostname or proxy.username is not None
                or proxy.password is not None or proxy.path not in ("", "/")
                or proxy.query or proxy.fragment):
            raise ValueError("--mitmproxy must be a regular HTTP proxy URL, e.g. http://127.0.0.1:8080")
        self.host = proxy.hostname
        self.port = proxy.port if proxy.port is not None else 8080
        if not 1 <= self.port <= 65535:
            raise ValueError("--mitmproxy needs a valid TCP port")
        self.timeout = timeout
        self.queue: queue.Queue[dict] = queue.Queue(maxsize=queue_size)
        self.stopping = threading.Event()
        self.forwarded = self.failed = self.dropped = 0
        self.thread = threading.Thread(target=self._run, name="mitmproxy-forwarder", daemon=True)
        self.thread.start()

    def submit(self, record: dict) -> bool:
        if self.stopping.is_set():
            return False
        try:
            self.queue.put_nowait(record)
            return True
        except queue.Full:
            self.dropped += 1
            print("[warning] proxy queue full; request remains in JSONL for --replay", file=sys.stderr)
            return False

    def _post(self, record: dict) -> None:
        body = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        # Explicit absolute-form HTTP proxy request; ignores NO_PROXY/env settings.
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", CAPTURE_URL, body=body, headers={
                "Content-Type": "application/json", "X-WeChat-Frida-Capture": "1"
            })
            response = connection.getresponse()
            reply = response.read(4096)
            if response.status != 204 or response.getheader("X-WeChat-Capture-Ack") != "request-only":
                detail = reply.decode("utf-8", "replace")[:256]
                raise RuntimeError(f"proxy returned {response.status}: {detail}; check the request-only addon")
        finally:
            connection.close()

    def _run(self) -> None:
        while not self.stopping.is_set() or not self.queue.empty():
            try:
                record = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._post(record)
                self.forwarded += 1
            except Exception as error:
                self.failed += 1
                print(f"[warning] mitmproxy: {error}; request remains in JSONL for --replay", file=sys.stderr)
            finally:
                self.queue.task_done()

    def close(self, timeout: float = 10.0) -> bool:
        self.stopping.set()
        self.thread.join(timeout)
        drained = not self.thread.is_alive()
        print(f"[proxy] forwarded={self.forwarded} failed={self.failed} queue_dropped={self.dropped} pending={self.queue.unfinished_tasks}", file=sys.stderr)
        if not drained:
            print("[warning] proxy drain timed out; replay the JSONL to recover pending requests", file=sys.stderr)
        return drained and self.failed == 0 and self.dropped == 0


def replay(path: Path, forwarder: ProxyForwarder, max_bytes: int) -> int:
    count = 0
    errors = 0
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or record.get("type") != "request":
                    continue
                raw = base64.b64decode(record["request_body_b64"], validate=True)
                validated = request_record(record, raw, max_bytes)
                # Offline replay can wait for space without blocking the phone.
                forwarder.queue.put(validated)
                count += 1
            except (ValueError, KeyError, TypeError, binascii.Error) as error:
                errors += 1
                print(f"[warning] replay line {line_number}: {error}", file=sys.stderr)
    print(f"[replay] queued={count} invalid={errors}", file=sys.stderr)
    return errors


def resolve_pid(device, target: str) -> int:
    if target.isdecimal():
        return int(target)
    # On iOS, the bundle identifier differs from the process name (WeChat).
    try:
        applications = device.enumerate_applications(scope="minimal")
    except Exception:
        applications = []  # Gadget may expose only process enumeration.
    for app in applications:
        if app.identifier == target:
            if not app.pid:
                raise RuntimeError(f"{target} is not running; open it or add --spawn")
            return app.pid
    return device.get_process(target).pid


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--process", default="com.tencent.xin", help="iOS bundle ID, process name, or PID")
    parser.add_argument("--spawn", action="store_true", help="spawn the bundle ID and install hooks before resuming")
    devices = parser.add_mutually_exclusive_group()
    devices.add_argument("--device", "--remote", dest="remote", metavar="HOST:PORT", help="Frida server/Gadget address; otherwise use USB")
    devices.add_argument("--device-id", help="specific Frida device ID")
    parser.add_argument("--hook", type=Path, default=Path(__file__).with_name("mmtls_hook.js"))
    parser.add_argument("--output", type=Path, default=Path("wechat-ios-requests.jsonl"))
    parser.add_argument("--mitmproxy", metavar="URL", help="regular HTTP proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--replay", type=Path, metavar="JSONL", help="forward a saved request log without a phone or Frida")
    parser.add_argument("--cgi", action="append", type=int, default=[], help="only capture this CGI ID; repeat for several IDs")
    parser.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024, help="maximum request size; oversized bodies are skipped, never truncated")
    parser.add_argument("--queue-size", type=int, default=256, help="bounded mitmproxy forwarding queue")
    parser.add_argument("--verbose", action="store_true", help="include serializer diagnostics")
    parser.add_argument("--no-transport", action="store_true", help="capture only the identified protobuf CGI packer")
    args = parser.parse_args(argv)
    if not 1 <= args.max_bytes <= MAX_BODY_BYTES:
        parser.error("--max-bytes must be between 1 and 16777216")
    if args.queue_size < 1:
        parser.error("--queue-size must be positive")
    if any(cgi < 0 or cgi > 0xFFFFFFFF for cgi in args.cgi):
        parser.error("--cgi must be an unsigned 32-bit integer")
    if args.replay and not args.mitmproxy:
        parser.error("--replay requires --mitmproxy")
    if args.spawn and args.process.isdecimal():
        parser.error("--spawn requires a bundle ID, not a PID")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    forwarder = None
    try:
        if args.mitmproxy:
            forwarder = ProxyForwarder(args.mitmproxy, args.queue_size)
        if args.replay:
            errors = replay(args.replay, forwarder, args.max_bytes)
            delivered = forwarder.close(timeout=60.0)
            forwarder = None
            return 0 if not errors and delivered else 1
        try:
            import frida
        except ImportError as error:
            raise RuntimeError("Install the driver dependency: python -m pip install frida") from error

        source = args.hook.read_text(encoding="utf-8")
        config = {
            "maxBodyBytes": args.max_bytes, "cgis": args.cgi,
            "verbose": args.verbose, "captureTransport": not args.no_transport
        }
        source = "globalThis.__WECHAT_IOS_CAPTURE_CONFIG__ = " + json.dumps(config) + ";\n" + source
        if args.remote:
            device = frida.get_device_manager().add_remote_device(args.remote)
        elif args.device_id:
            device = frida.get_device(args.device_id, timeout=10)
        else:
            device = frida.get_usb_device(timeout=10)

        session = script = None
        spawned_pid = None
        resumed = False
        done = threading.Event()
        fatal = threading.Event()
        saved = 0
        file_lock = threading.Lock()
        # Append permits reconnecting without losing previous requests.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("a", encoding="utf-8") as output:
            def on_message(message, data):
                nonlocal saved
                if message.get("type") == "error":
                    print("[hook error] " + str(message.get("stack") or message.get("description")), file=sys.stderr)
                    fatal.set()
                    done.set()
                    return
                payload = message.get("payload")
                if message.get("type") != "send" or not isinstance(payload, dict):
                    return
                if payload.get("type") == "status":
                    level = payload.get("level", "info")
                    if args.verbose or level in ("ready", "warning", "fatal"):
                        print(f"[{level}] {payload.get('message', '')}", file=sys.stderr)
                    if level == "fatal":
                        fatal.set()
                        done.set()
                    return
                if payload.get("type") != "request":
                    return
                try:
                    record = request_record(payload, data, args.max_bytes)
                    with file_lock:
                        output.write(json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n")
                        output.flush()
                        saved += 1
                    if forwarder:
                        forwarder.submit(record)
                    print(
                        f"[request] layer={record.get('capture_layer')} source={record.get('source')} "
                        f"CGI={record.get('cgi')} task={record.get('task_id')} bytes={record['body_length']} "
                        f"{record.get('host') or 'unknown.invalid'}{record.get('uri') or '/'}",
                        file=sys.stderr,
                    )
                except Exception as error:
                    print(f"[capture error] {error}", file=sys.stderr)
                    fatal.set()
                    done.set()

            def on_detached(reason, crash=None):
                if not done.is_set():
                    print(f"[detached] {reason}", file=sys.stderr)
                    if reason != "application-requested":
                        fatal.set()
                done.set()

            try:
                if args.spawn:
                    spawned_pid = device.spawn([args.process])
                    pid = spawned_pid
                else:
                    pid = resolve_pid(device, args.process)
                session = device.attach(pid)
                session.on("detached", on_detached)
                script = session.create_script(source, name="wechat-ios-request-capture")
                script.on("message", on_message)
                script.load()
                result = script.exports_sync.init()
                print(
                    f"[build] {result['build_uuid']} PID={pid}; transport_ready="
                    f"{result.get('transport_ready', False)}; requests append to {args.output}",
                    file=sys.stderr,
                )
                if result.get("transport_pending"):
                    print("[warning] transport hooks pending: " + ", ".join(result["transport_pending"]), file=sys.stderr)
                if spawned_pid is not None:
                    device.resume(spawned_pid)
                    resumed = True
                if not result["ready"]:
                    print("[startup] waiting for Objective-C classes after resume", file=sys.stderr)
                print("[capture] use WeChat; Ctrl-C stops capture", file=sys.stderr)
                while not done.wait(0.5):
                    pass
            except KeyboardInterrupt:
                done.set()
            finally:
                done.set()
                if spawned_pid is not None and not resumed:
                    try:
                        device.resume(spawned_pid)
                    except Exception:
                        pass
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        pass
            print(f"[capture] saved={saved}", file=sys.stderr)
        delivered = forwarder.close() if forwarder else True
        forwarder = None
        return 1 if fatal.is_set() or not delivered else 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f"[error] {error}", file=sys.stderr)
        return 1
    finally:
        if forwarder is not None:
            forwarder.close()


if __name__ == "__main__":
    raise SystemExit(main())
