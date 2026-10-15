"""Reconstruct Android exchanges and iOS request snapshots from Frida captures."""

import base64
import json
from urllib.parse import urlsplit

from mitmproxy import ctx, http


CAPTURE_HOST = "capture.invalid"
ANDROID_CAPTURE_PATH = "/__frida_mmtls"
IOS_CAPTURE_PATH = "/__frida_wechat_ios_request"
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_ENVELOPE_BYTES = 32 * 1024 * 1024


# Android: a completed request/response exchange.
def _body(payload, field):
    value = payload.get(field) or ''
    return base64.b64decode(value.encode('ascii'), validate=True) if value else b''


def _render_body(payload, body_field, content_type_field, status_field):
    """Return the exact captured bytes and their original content type."""
    raw_body = _body(payload, body_field)
    original_type = str(payload.get(content_type_field) or 'application/octet-stream')
    status = payload.get(status_field)
    representation = ('raw-protobuf' if original_type == 'application/x-protobuf'
                       else 'raw-captured-bytes')
    return raw_body, original_type, representation, status


def _host_and_path(payload):
    host = str(payload.get('host') or '').strip()
    uri = str(payload.get('uri') or '/')
    parsed = urlsplit(uri)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or host
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
    else:
        path = uri if uri.startswith('/') else '/' + uri
    if not host:
        host = 'unknown.invalid'
    return host, path


class MmtlsCaptureAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        if (flow.request.pretty_host != CAPTURE_HOST or
                flow.request.path.split('?', 1)[0] != ANDROID_CAPTURE_PATH):
            return

        try:
            payload = json.loads((flow.request.raw_content or b'{}').decode('utf-8'))
            if payload.get('type') != 'exchange':
                raise ValueError('expected an exchange event')
            host, path = _host_and_path(payload)
            request_body, request_type, request_representation, request_status = _render_body(
                payload, 'request_body_b64', 'request_content_type',
                'request_plaintext_status')
            response_body, response_type, response_representation, response_status = _render_body(
                payload, 'response_body_b64', 'response_content_type',
                'response_plaintext_status')

            # Replace the local ingestion request with the captured app exchange.
            flow.request.method = 'POST'
            flow.request.scheme = 'https'
            flow.request.host = host
            flow.request.port = 443
            flow.request.path = path
            flow.request.http_version = 'HTTP/1.1'
            flow.request.headers.clear()
            flow.request.headers['Host'] = host
            flow.request.headers['Content-Type'] = request_type
            flow.request.headers['X-Frida-Original-Content-Type'] = str(
                payload.get('request_content_type') or 'application/octet-stream')
            flow.request.headers['X-Frida-Body-Representation'] = request_representation
            if request_status:
                flow.request.headers['X-Frida-Plaintext-Status'] = str(request_status)
            flow.request.headers['X-Frida-Exchange-ID'] = str(payload.get('id') or '')
            flow.request.headers['X-Frida-Capture-Layer'] = str(
                payload.get('capture_layer', 'app-protobuf'))
            if payload.get('task_id') is not None:
                flow.request.headers['X-Frida-Task-ID'] = str(payload.get('task_id'))
            if payload.get('debug_info'):
                flow.request.headers['X-Frida-Debug-Info'] = str(payload.get('debug_info'))[:256]
            route = payload.get('mmtls_route') or {}
            flow.request.headers['X-Frida-MMTLS-Route'] = str(route.get('source', 'unknown'))
            flow.request.content = request_body

            response_headers = {
                'Content-Type': response_type,
                'X-Frida-Original-Content-Type': str(
                    payload.get('response_content_type') or 'application/octet-stream'),
                'X-Frida-Body-Representation': response_representation,
                'X-Frida-App-Result-Code': str(payload.get('app_result_code', '')),
                'X-Frida-Capture': 'app-payload-snapshot',
                'X-Frida-Capture-Layer': str(payload.get('capture_layer', 'app-protobuf'))
            }
            if response_status:
                response_headers['X-Frida-Plaintext-Status'] = str(response_status)
            if payload.get('response_body_stage'):
                response_headers['X-Frida-Response-Stage'] = str(
                    payload['response_body_stage'])
            flow.response = http.Response.make(200, response_body, response_headers)
            flow.comment = 'Synthetic WeChat exchange; bodies contain exact captured bytes'
        except Exception as error:
            flow.response = http.Response.make(
                400, ('invalid Frida capture: ' + str(error)).encode('utf-8'),
                {'Content-Type': 'text/plain; charset=utf-8'}
            )


# iOS: a captured request with a local acknowledgement.
def is_capture(flow: http.HTTPFlow) -> bool:
    return flow.request.host == CAPTURE_HOST and flow.request.path.split("?", 1)[0] == IOS_CAPTURE_PATH


def host_and_path(payload: dict) -> tuple[str, str, int, str]:
    uri = str(payload.get("uri") or "/")
    host = str(payload.get("host") or "unknown.invalid")
    if any(ord(char) < 32 or char.isspace() for char in uri + host):
        raise ValueError("invalid host/URI characters")
    parsed = urlsplit(uri)
    if parsed.scheme:
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URI must be a relative CGI path or an http(s) URL")
        scheme = parsed.scheme
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    else:
        scheme = "https"
        authority = urlsplit("//" + host)
        if not authority.hostname or authority.username or authority.password or authority.path or authority.query or authority.fragment or parsed.netloc:
            raise ValueError("invalid host")
        host = authority.hostname
        port = authority.port if authority.port is not None else 443
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        if parsed.query:
            path += "?" + parsed.query
    if port < 1 or port > 65535:
        raise ValueError("invalid port")
    return scheme, host.encode("idna").decode("ascii"), port, path


def header(value) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").encode("ascii", "backslashreplace").decode("ascii")[:512]


class WeChatIosRequestCapture:
    def load(self, loader) -> None:
        loader.add_option("wechat_ios_view", str, "raw", "Captured body display: raw protobuf bytes or a schema-free JSON wire preview")

    def configure(self, updated) -> None:
        if ctx.options.wechat_ios_view not in ("raw", "json"):
            from mitmproxy.exceptions import OptionsError
            raise OptionsError("wechat_ios_view must be raw or json")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if is_capture(flow):
            # Preserve ingestion bodies even if global large-body streaming is enabled.
            flow.request.stream = False

    def request(self, flow: http.HTTPFlow) -> None:
        if not is_capture(flow):
            return
        # Set a LOCAL response before changing host/path. No target server is contacted.
        flow.response = http.Response.make(204, b"", {"X-WeChat-Capture-Ack": "request-only"})
        try:
            envelope = flow.request.raw_content or b""
            if len(envelope) > MAX_ENVELOPE_BYTES:
                raise ValueError("capture envelope exceeds 32 MiB")
            payload = json.loads(envelope.decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("type") != "request" or payload.get("schema_version") != 1:
                raise ValueError("expected request event schema_version=1")
            encoded = payload.get("request_body_b64")
            if not isinstance(encoded, str):
                raise ValueError("missing request_body_b64")
            body = base64.b64decode(encoded, validate=True)
            if len(body) > MAX_BODY_BYTES or type(payload.get("body_length")) is not int or len(body) != payload["body_length"]:
                raise ValueError("request body size mismatch or size limit exceeded")
            content_type = payload.get("request_content_type", "application/x-protobuf")
            if content_type not in ("application/x-protobuf", "application/octet-stream"):
                raise ValueError("unsupported captured request content type")
            scheme, host, port, path = host_and_path(payload)
            representation = "raw-captured-bytes"
            if ctx.options.wechat_ios_view == "json":
                body = json.dumps(payload.get("request_view") or {"note": "No wire preview supplied"}, ensure_ascii=True, allow_nan=False, indent=2).encode("utf-8")
                content_type = "application/json; charset=utf-8"
                representation = "schema-free-wire-preview"
            flow.metadata["wechat_ios_capture"] = payload
            flow.request.method = "POST"
            flow.request.scheme = scheme
            flow.request.host = host
            flow.request.port = port
            flow.request.path = path
            flow.request.http_version = "HTTP/1.1"
            flow.request.headers.clear()
            authority = "[" + host + "]" if ":" in host else host
            if port != (443 if scheme == "https" else 80):
                authority += ":" + str(port)
            flow.request.headers["Host"] = authority
            flow.request.headers["Content-Type"] = content_type
            flow.request.headers["X-Frida-Capture"] = "request-snapshot"
            flow.request.headers["X-Frida-Body-Representation"] = representation
            for name, field in (
                ("Request-ID", "id"), ("CGI", "cgi"), ("CGI-Name", "cgi_name"),
                ("Task-ID", "task_id"), ("Sequence-ID", "sequence_id"),
                ("Source", "source"), ("Request-Class", "request_class"),
                ("Build-UUID", "build_uuid"), ("Plaintext-Status", "request_plaintext_status"),
                ("Capture-Layer", "capture_layer"), ("Transport-Path", "transport_path"),
                ("Record-Type", "record_type"), ("Record-Sequence", "record_sequence_hex"),
                ("Request-Semantics", "request_semantics")
            ):
                if payload.get(field) is not None:
                    flow.request.headers["X-Frida-" + name] = header(payload[field])
            flow.request.content = body
            flow.comment = (
                f"WeChat request capture; layer={payload.get('capture_layer')} "
                f"source={payload.get('source')} CGI={payload.get('cgi')} "
                f"task={payload.get('task_id')}; local 204 acknowledgement"
            )
        except Exception as error:
            flow.response = http.Response.make(400, ("invalid request capture: " + str(error)).encode("utf-8"), {"Content-Type": "text/plain; charset=utf-8"})
            flow.comment = "Rejected Frida request capture"


addons = [MmtlsCaptureAddon(), WeChatIosRequestCapture()]
