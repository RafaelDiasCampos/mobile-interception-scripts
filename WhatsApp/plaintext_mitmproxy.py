import base64
import json
import logging

from mitmproxy import http


DEBUG_HOST = "whatsapp-debug.invalid"
ANDROID_PATH = "/whatsapp/plaintext"
ANDROID_MARKER = "plaintext-v1"
ANDROID_ACK = {"X-WA-Plaintext-Ack": "1", "Cache-Control": "no-store"}
IOS_ACK = {"X-WA-ENC-Receiver": "1", "Content-Type": "application/json"}
HEALTH_ACK = {**ANDROID_ACK, **IOS_ACK}


def is_android_capture(flow: http.HTTPFlow) -> bool:
    return (
        flow.request.method == "POST"
        and flow.request.path.split("?", 1)[0] == ANDROID_PATH
        and flow.request.headers.get("x-wa-frida-debug") == ANDROID_MARKER
    )


def requestheaders(flow: http.HTTPFlow) -> None:
    if flow.request.host.lower() == DEBUG_HOST:
        flow.request.stream = False


def request(flow: http.HTTPFlow) -> None:
    if flow.request.host.lower() != DEBUG_HOST:
        return
    # Handle this reserved host locally; never forward captures upstream.
    if flow.request.method == "GET" and flow.request.path == "/__health":
        flow.response = http.Response.make(200, b'{"receiver":"whatsapp","ok":true}', HEALTH_ACK)
        return
    if is_android_capture(flow):
        capture_id = flow.request.headers.get("x-wa-capture-id", "unknown")
        flow.metadata["whatsapp_plaintext_debug"] = True
        flow.metadata["whatsapp_capture_id"] = capture_id
        flow.metadata["whatsapp_hook"] = flow.request.headers.get("x-wa-hook", "")
        flow.comment = f"WhatsApp plaintext {capture_id}"
        flow.marked = "*"
        flow.response = http.Response.make(204, b"", ANDROID_ACK)
        logging.info("[wa-plaintext] received %s (%d bytes)",
                     capture_id, len(flow.request.raw_content or b""))
        return
    if flow.request.method != "POST":
        flow.response = http.Response.make(405, b'{"error":"POST required"}', IOS_ACK)
        return
    if not flow.request.headers.get("X-WA-Capture-Metadata"):
        flow.response = http.Response.make(
            400, b"Invalid WhatsApp plaintext debug request\n",
            {"Content-Type": "text/plain", "Cache-Control": "no-store"},
        )
        return
    try:
        raw = flow.request.headers["X-WA-Capture-Metadata"]
        metadata = json.loads(base64.b64decode(raw, validate=True).decode("utf-8"))
        if not isinstance(metadata, dict) or metadata.get("kind") != "plaintext":
            raise ValueError("Invalid capture metadata")
        body = flow.request.raw_content or b""
        if metadata.get("byte_length") != len(body):
            raise ValueError("Plaintext byte length does not match metadata")
        flow.metadata["wa_enc_capture"] = metadata
        response = json.dumps({"ok": True, "bytes": len(body),
                               "sequence": metadata.get("sequence")}).encode()
        flow.response = http.Response.make(200, response, IOS_ACK)
    except (ValueError, UnicodeError) as error:
        flow.response = http.Response.make(400, json.dumps({"error": str(error)}).encode(), IOS_ACK)
