import argparse
import base64
from collections import Counter, defaultdict
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path


MAX_PROTOBUF_INSPECT_BYTES = 1024 * 1024
MAX_PROTOBUF_FIELDS = 512
MAX_PROTOBUF_TEXT_CHARS = 16384
CAPTURE_FORMAT = 'plaintext-json-v5'


def prepare_hook(hook_path, include_business_crypto=False, verbose=False):
    source = hook_path.read_text(encoding='utf-8')
    replacements = {
        'const CAPTURE_BUSINESS_CRYPTO = true;':
            'const CAPTURE_BUSINESS_CRYPTO = {};'.format(
                'true' if include_business_crypto else 'false'),
        'const CAPTURE_TRACE_EVENTS = true;':
            'const CAPTURE_TRACE_EVENTS = {};'.format('true' if verbose else 'false'),
    }
    for marker, replacement in replacements.items():
        source = source.replace(marker, replacement)
    if 'frida-java-bridge' not in source:
        return source

    bundle_path = hook_path.with_name(hook_path.stem + '.bundle.js')
    compiler = shutil.which('frida-compile')
    if not compiler:
        raise RuntimeError(
            'This hook imports frida-java-bridge and must be bundled. Install frida-tools '
            'and run `npm install frida-java-bridge` in the toolkit directory.'
        )
    temp_source = hook_path.with_name('.' + hook_path.stem + '.capture.js')
    try:
        temp_source.write_text(source, encoding='utf-8')
        subprocess.run(
            [compiler, str(temp_source), '-o', str(bundle_path)],
            cwd=str(hook_path.parent), check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as error:
        details = (error.stderr or error.stdout or '').strip()
        raise RuntimeError('frida-compile failed: ' + (details or str(error))) from error
    finally:
        try:
            temp_source.unlink()
        except FileNotFoundError:
            pass
    return bundle_path.read_text(encoding='utf-8')


def _read_varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError('truncated varint')
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError('varint exceeds 64 bits')
        value |= (byte & 0x7f) << (index * 7)
        if byte < 0x80:
            return value, offset
    raise ValueError('varint exceeds 10 bytes')


def _protobuf_fields(data, depth=0):
    fields = []
    offset = 0
    while offset < len(data) and len(fields) < MAX_PROTOBUF_FIELDS:
        key, offset = _read_varint(data, offset)
        number, wire_type = key >> 3, key & 7
        if number == 0:
            raise ValueError('field number 0 is invalid')
        field = {'number': number, 'wire_type': wire_type}
        if wire_type == 0:
            field['value'], offset = _read_varint(data, offset)
        elif wire_type in (1, 5):
            size = 8 if wire_type == 1 else 4
            end = offset + size
            if end > len(data):
                raise ValueError('truncated fixed-width field')
            value = data[offset:end]
            field['value'] = struct.unpack('<Q' if size == 8 else '<I', value)[0]
            field['hex'] = value.hex()
            offset = end
        elif wire_type == 2:
            size, offset = _read_varint(data, offset)
            end = offset + size
            if end > len(data):
                raise ValueError('truncated length-delimited field')
            value = data[offset:end]
            field['length'] = size
            try:
                text = value.decode('utf-8')
                if len(text) <= MAX_PROTOBUF_TEXT_CHARS and all(
                        char.isprintable() or char in '\t\r\n' for char in text):
                    field['text'] = text
            except UnicodeDecodeError:
                pass
            if depth < 3 and value and 'text' not in field:
                try:
                    nested = _protobuf_fields(value, depth + 1)
                    if nested:
                        field['message_candidate'] = nested
                except ValueError:
                    pass
            offset = end
        else:
            raise ValueError('unsupported protobuf wire type {}'.format(wire_type))
        fields.append(field)

    if offset < len(data):
        raise ValueError('protobuf field limit reached')
    return fields


def _plaintext_view(data, source, include_base64=False):
    result = {
        'source': source,
        'length_bytes': len(data),
        'format': 'protobuf-wire',
        'schema_applied': False,
    }
    if include_base64:
        result['bytes_base64'] = base64.b64encode(data).decode('ascii')
    if len(data) > MAX_PROTOBUF_INSPECT_BYTES:
        result['parse_ok'] = False
        result['parse_error'] = 'payload exceeds protobuf inspection limit'
        return result
    try:
        result['fields'] = _protobuf_fields(data)
        result['parse_ok'] = True
    except ValueError as error:
        result['parse_ok'] = False
        result['parse_error'] = str(error)
    text_fields = []

    def collect_text(fields, parents=()):
        for field in fields:
            path = parents + (field.get('number'),)
            if 'text' in field and len(text_fields) < 256:
                text_fields.append({'field_path': list(path), 'value': field['text']})
            nested = field.get('message_candidate')
            if isinstance(nested, list):
                collect_text(nested, path)

    if result.get('parse_ok'):
        collect_text(result.get('fields', []))
    if text_fields:
        result['text_fields'] = text_fields
        result['text'] = '\n'.join(item['value'] for item in text_fields)
    try:
        text = data.decode('utf-8')
        if len(text) <= MAX_PROTOBUF_TEXT_CHARS and all(
                char.isprintable() or char in '\t\r\n' for char in text):
            result['text'] = text
    except UnicodeDecodeError:
        pass
    return result


def _find_byte_snapshot(value):
    if not isinstance(value, dict):
        return None
    if value.get('class_name') == '[B':
        return value
    fields = value.get('fields')
    if isinstance(fields, dict):
        nested = fields.get('value')
        if isinstance(nested, dict) and nested.get('class_name') == '[B':
            return nested
    return None


def add_plaintext_view(payload):
    """Add a generic Protobuf view while preserving the original captured bytes."""
    kind = payload.get('type')
    if kind in ('request', 'response'):
        if payload.get('capture_layer') == 'stn-callback-buffer':
            payload['plaintext_status'] = (
                'opaque-stn-buffer; it may still contain business-layer ciphertext')
            return
        body_field = 'request_body_b64' if kind == 'request' else 'response_body_b64'
        content_type_field = 'request_content_type' if kind == 'request' else 'response_content_type'
        if payload.get(content_type_field) != 'application/x-protobuf':
            payload['plaintext_status'] = 'no-protobuf-payload-at-this-capture-layer'
            return
        encoded = payload.get(body_field) or ''
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as error:
            payload['plaintext'] = {'format': 'protobuf-wire', 'parse_ok': False,
                                    'parse_error': 'invalid Base64: {}'.format(error)}
            payload['plaintext_status'] = 'protobuf-decode-failed'
            return
        if kind == 'request':
            source = 'O8 request protobuf before transport packing'
        else:
            source = payload.get('response_body_stage') or (
                'O8 response body; capture stage was not recorded by this hook version')
        payload['plaintext'] = _plaintext_view(body, source, include_base64=False)
        payload['plaintext_status'] = (
            'protobuf-wire-decoded' if payload['plaintext']['parse_ok']
            else 'protobuf-wire-parse-failed')
        return

    if kind != 'business_crypto':
        return
    payload.pop('plaintext', None)
    payload.pop('plaintext_candidate', None)
    method = payload.get('method')
    candidate_only = False
    if method in ('pack', 'packHybrid', 'packHybridEcdh'):
        args = payload.get('args_before') or []
        candidates = []
        for index, value in enumerate(args):
            if not isinstance(value, dict) or value.get('class_name') != '[B':
                continue
            snapshot = value
            if snapshot and snapshot.get('base64') and snapshot.get('length'):
                candidates.append((int(snapshot['length']), index, snapshot))
        if not candidates:
            return
        if method == 'pack' and any(index == 0 for _, index, _ in candidates):
            _, index, snapshot = next(x for x in candidates if x[1] == 0)
            source = 'MMProtocalJni.pack input args_before[0]'
        else:
            _, index, snapshot = max(candidates, key=lambda item: item[0])
            source = ('MMProtocalJni.{} largest non-empty byte[] input '
                      'args_before[{}]').format(method, index)
            candidate_only = True
    elif method == 'unpack':
        args = payload.get('args_after') or []
        index, source = 0, 'MMProtocalJni.unpack output args_after[0].fields.value'
        if index >= len(args):
            return
        snapshot = _find_byte_snapshot(args[index])
    else:
        return
    if not snapshot or not snapshot.get('base64'):
        return
    try:
        body = base64.b64decode(snapshot['base64'], validate=True)
    except (ValueError, TypeError):
        return
    if body:
        view = _plaintext_view(body, source, include_base64=(method == 'unpack'))
        if candidate_only:
            view['classification'] = 'unverified-byte-array-candidate'
            payload['plaintext_candidate'] = view
            payload['plaintext_status'] = 'unverified-byte-array-candidate'
        else:
            payload['plaintext'] = view
            payload['plaintext_status'] = (
                'protobuf-wire-decoded' if view.get('parse_ok')
                else 'protobuf-wire-parse-failed')


def decode_existing_jsonl(path):
    """Enrich an existing JSONL file in place, preserving its records and order."""
    temp_path = None
    stats = Counter()
    try:
        with path.open('r', encoding='utf-8') as source:
            with tempfile.NamedTemporaryFile(
                    'w', encoding='utf-8', newline='\n',
                    dir=str(path.parent), prefix='.' + path.name + '.',
                    suffix='.tmp', delete=False) as target:
                temp_path = Path(target.name)
                for line_number, line in enumerate(source, 1):
                    if not line.strip():
                        target.write(line)
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError('invalid JSON on line {}: {}'.format(
                            line_number, error)) from error
                    if not isinstance(payload, dict):
                        target.write(line)
                        stats['non_object'] += 1
                        continue
                    add_plaintext_view(payload)
                    if 'plaintext' in payload:
                        stats['plaintext'] += 1
                        if payload['plaintext'].get('parse_ok'):
                            stats['parse_ok'] += 1
                        else:
                            stats['parse_failed'] += 1
                    if 'plaintext_candidate' in payload:
                        stats['candidate'] += 1
                    if payload.get('plaintext_status', '').startswith('opaque-stn'):
                        stats['opaque_stn'] += 1
                    target.write(json.dumps(payload, ensure_ascii=False,
                                            separators=(',', ':')) + '\n')
        if path.exists():
            os.chmod(str(temp_path), stat.S_IMODE(path.stat().st_mode))
        os.replace(str(temp_path), str(path))
        return stats
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--process', default='com.tencent.mm',
                        help='Android process to attach (default: %(default)s)')
    parser.add_argument('--also-process', action='append', default=[], metavar='NAME',
                        help='also attach to this process; may be repeated (use com.tencent.mm:push for STN callbacks)')
    parser.add_argument('--device', metavar='HOST',
                        help='Frida remote device endpoint, e.g. 127.0.0.1:27042')
    parser.add_argument('--spawn', action='store_true',
                        help='spawn the target app first; selecting :push spawns com.tencent.mm but hooks only requested processes')
    parser.add_argument('--output', default='wechat-mmtls.jsonl',
                        help='JSON Lines output path (default: %(default)s)')
    parser.add_argument('--hook', default=str(Path(__file__).with_name('mmtls_hook.js')),
                        help='Frida JavaScript hook file')
    parser.add_argument('--mitmproxy', metavar='URL',
                        help='regular HTTP proxy listener, e.g. http://127.0.0.1:8080 (not the SOCKS5 listener)')
    parser.add_argument('--mmtls-only', action='store_true',
                        help='write/forward only hosts matched to the observed MMTLS map or APK test list')
    parser.add_argument('--verbose', action='store_true',
                        help='print per-call Frida traces and capture lines (default: compact logs)')
    parser.add_argument('--include-business-crypto', action='store_true',
                        help='capture full pack/unpack argument snapshots; compact unpack plaintext is on by default')
    parser.add_argument('--decode-existing', action='store_true',
                        help='add generic Protobuf views to existing JSONL at --output, then exit')
    args = parser.parse_args(argv)

    output_path = Path(args.output).expanduser().resolve()
    if args.decode_existing:
        try:
            stats = decode_existing_jsonl(output_path)
        except Exception as error:
            print('[error] could not decode {}: {}'.format(output_path, error), file=sys.stderr)
            return 1
        print('[decode] {} plaintext={} parsed={} failed={} candidates={} opaque_stn={}'.format(
            output_path, stats['plaintext'], stats['parse_ok'], stats['parse_failed'],
            stats['candidate'], stats['opaque_stn']), file=sys.stderr)
        return 0

    if args.mitmproxy:
        proxy_url = urlsplit(args.mitmproxy)
        if proxy_url.scheme.lower() not in ('http', 'https') or not proxy_url.hostname:
            print('[error] --mitmproxy needs a regular HTTP proxy URL. If mitmproxy is also '
                  'used in SOCKS5 mode, start a regular listener on another port and point '
                  '--mitmproxy at that port.', file=sys.stderr)
            return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path = Path(args.hook).expanduser().resolve()
    try:
        hook_source = prepare_hook(hook_path, args.include_business_crypto, args.verbose)
    except Exception as error:
        print('[error] {}'.format(error), file=sys.stderr)
        return 1
    try:
        import frida
    except ImportError as error:
        print('[error] install frida-tools before live capture: {}'.format(error), file=sys.stderr)
        return 1
    opener = None
    if args.mitmproxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({'http': args.mitmproxy})
        )

    output = output_path.open('a', encoding='utf-8', buffering=1)
    print('[ready] writing JSONL to {} ({}, compact logs{})'.format(
        output_path, CAPTURE_FORMAT,
        ', full business-crypto included' if args.include_business_crypto
        else ', unpack plaintext enabled'),
        file=sys.stderr)
    pending_requests = {}
    event_counts = defaultdict(Counter)
    proxy_counts = Counter()

    def count_event(payload, source_process, kind):
        process_name = payload.get('frida_process') or source_process or 'unknown'
        event_counts[process_name][kind] += 1
        plaintext = payload.get('plaintext')
        if isinstance(plaintext, dict):
            event_counts[process_name]['plaintext_parse_ok' if plaintext.get('parse_ok')
                                       else 'plaintext_parse_failed'] += 1

    def print_summary():
        for process_name in sorted(event_counts):
            counts = event_counts[process_name]
            print('[summary] {} requests={} responses={} business_crypto={} plaintext_parse_ok={} plaintext_parse_failed={}'.format(
                process_name, counts['request'], counts['response'], counts['business_crypto'],
                counts['plaintext_parse_ok'], counts['plaintext_parse_failed']),
                file=sys.stderr)
        if args.mitmproxy:
            print('[summary] mitmproxy forwarded={} failed={}'.format(
                proxy_counts['forwarded'], proxy_counts['failed']), file=sys.stderr)

    def write_event(payload):
        output.write(json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n')
        output.flush()

    def forward_exchange(payload):
        if not opener:
            return
        try:
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            request = urllib.request.Request(
                'http://capture.invalid/__frida_mmtls',
                data=body,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with opener.open(request, timeout=5) as response:
                response.read()
                proxy_counts['forwarded'] += 1
        except Exception as error:  # preserve the JSONL capture if proxy forwarding fails
            proxy_counts['failed'] += 1
            if proxy_counts['failed'] <= 3:
                print('[mitmproxy] forward failed: {}'.format(error), file=sys.stderr)

    def on_message(message, data, source_process=None):
        source_prefix = '[{}] '.format(source_process) if source_process else ''
        if message.get('type') == 'error':
            print(source_prefix + '[frida] ' + message.get('stack', message.get('description', 'hook error')),
                  file=sys.stderr)
            return
        payload = message.get('payload') or {}
        if source_process and isinstance(payload, dict):
            payload.setdefault('frida_process', source_process)
        kind = payload.get('type')
        if kind in ('request', 'response', 'business_crypto'):
            try:
                add_plaintext_view(payload)
            except Exception as error:
                print(source_prefix + '[plaintext] decode failed: {}'.format(error),
                      file=sys.stderr)
        if kind == 'status':
            hooks = payload.get('business_crypto_hooks', payload.get('hooks'))
            if args.verbose:
                print(source_prefix + '[hook] ' + payload.get('message', 'ready'), file=sys.stderr)
                if hooks is not None:
                    names = ', '.join(hooks) if hooks else 'none found'
                    print(source_prefix + '[hook] MMProtocalJni overloads: {}'.format(names),
                          file=sys.stderr)
            elif payload.get('message') == 'WeChat Mars/STN capture hooks installed':
                print(source_prefix + '[hook] ready', file=sys.stderr)
            return
        if kind == 'diagnostic':
            print(source_prefix + '[hook] {}: {}'.format(payload.get('stage'), payload.get('error')),
                  file=sys.stderr)
            return
        if kind == 'trace':
            if not args.verbose:
                return
            details = json.dumps(payload.get('details') or {}, ensure_ascii=False,
                                 separators=(',', ':'))
            print(source_prefix + '[trace] {}{} hit #{}'.format(
                payload.get('hook', '?'),
                (' ' + payload.get('signature')) if payload.get('signature') else '',
                payload.get('hit_count', '?')),
                file=sys.stderr)
            if details != '{}':
                print('         ' + details, file=sys.stderr)
            return
        if kind == 'business_crypto':
            if args.mmtls_only:
                return
            if not args.include_business_crypto and payload.get('method') != 'unpack':
                return
            if not args.include_business_crypto and payload.get('correlated_to_bc'):
                return
            count_event(payload, source_process, kind)
            if args.include_business_crypto:
                write_event(payload)
            else:
                # Preserve the decrypted output and useful call metadata while
                # dropping encrypted inputs and duplicate snapshots.
                compact = {
                    key: payload[key] for key in (
                        'type', 'call_id', 'process_id', 'frida_process', 'thread_id',
                        'timestamp_ms', 'class_name', 'method', 'signature', 'outcome',
                        'error', 'plaintext', 'plaintext_status') if key in payload
                }
                write_event(compact)
            if args.verbose:
                print(source_prefix + '[business-layer] {} {} call={} (plaintext candidate saved to JSONL)'.format(
                    payload.get('method', '?'), payload.get('outcome', '?'),
                    payload.get('call_id', '?')), file=sys.stderr)
            return
        if kind not in ('request', 'response', 'exchange'):
            return
        if args.mmtls_only and not (payload.get('mmtls_route') or {}).get('matched'):
            return

        if kind == 'request':
            count_event(payload, source_process, kind)
            write_event(payload)
            pending_requests[payload.get('id')] = payload
            if args.verbose:
                print(source_prefix + '[capture request:{}] {} {} task={} id={}'.format(
                    payload.get('capture_layer', 'protobuf'),
                    payload.get('host') or '?', payload.get('uri') or '/',
                    payload.get('task_id') or '?',
                    payload.get('id') or ''), file=sys.stderr)
            return

        if kind == 'response':
            count_event(payload, source_process, kind)
            write_event(payload)
            request_event = pending_requests.pop(payload.get('id'), None)
            if args.verbose:
                print(source_prefix + '[capture response:{}] {} {} task={} id={}'.format(
                    payload.get('capture_layer', 'protobuf'),
                    payload.get('host') or '?', payload.get('uri') or '/',
                    payload.get('task_id') or '?',
                    payload.get('id') or ''), file=sys.stderr)
            if request_event and not payload.get('orphan_response'):
                exchange = dict(request_event)
                exchange.update(payload)
                exchange['type'] = 'exchange'
                exchange['request_plaintext'] = request_event.get('plaintext')
                exchange['response_plaintext'] = payload.get('plaintext')
                exchange['request_plaintext_status'] = request_event.get('plaintext_status')
                exchange['response_plaintext_status'] = payload.get('plaintext_status')
                exchange.pop('plaintext', None)
                forward_exchange(exchange)
            return

        # Accept records from an older hook version too.
        write_event(payload)
        forward_exchange(payload)

    sessions = []
    scripts = []
    pending_process_names = []

    def attach_process(process_name, target_pid=None):
        process = device.get_process(process_name) if target_pid is None else None
        pid = target_pid if target_pid is not None else process.pid
        session = device.attach(pid)
        script = session.create_script(hook_source)

        def handle_message(message, data):
            on_message(message, data, process_name)

        script.on('message', handle_message)
        script.load()
        sessions.append(session)
        scripts.append(script)
        print('[ready] attached to {} (pid {})'.format(process_name, pid), file=sys.stderr)

    try:
        device = (frida.get_device_manager().add_remote_device(args.device)
                  if args.device else frida.get_usb_device(timeout=10))
        wechat_main = 'com.tencent.mm'
        wechat_push = 'com.tencent.mm:push'
        requested_process_names = list(dict.fromkeys([args.process] + list(args.also_process)))
        # Android creates :push as a child of the main app. When :push itself is
        # requested with --spawn, start the package but instrument only requested processes.
        spawn_process_name = args.process
        spawn_without_hook = False
        if args.spawn and args.process == wechat_push:
            spawn_process_name = wechat_main
            spawn_without_hook = wechat_main not in requested_process_names
            print('[hint] spawning the main WeChat app to create :push; only requested processes will be hooked',
                  file=sys.stderr)

        spawned_pid = None
        if args.spawn:
            try:
                spawned_pid = device.spawn(spawn_process_name)
            except Exception as spawn_error:
                # If the app is already running, attach to it instead of failing.
                try:
                    device.get_process(spawn_process_name)
                except frida.ProcessNotFoundError:
                    raise spawn_error
                print('[hint] {} is already running; attaching to the requested process(es)'.format(
                    spawn_process_name), file=sys.stderr)

            # If main is only needed to start :push, let it run without installing
            # hooks there. The requested child process is attached below or watched.
            if spawned_pid is not None and spawn_without_hook:
                device.resume(spawned_pid)
                spawned_pid = None

        process_names = list(requested_process_names)
        if args.spawn and not spawn_without_hook and spawn_process_name in process_names:
            process_names.remove(spawn_process_name)
            process_names.insert(0, spawn_process_name)
        for process_name in process_names:
            target_pid = spawned_pid if process_name == spawn_process_name else None
            try:
                process = device.get_process(process_name) if target_pid is None else None
            except frida.ProcessNotFoundError:
                if not args.spawn and process_name == args.process:
                    raise
                pending_process_names.append(process_name)
                print('[hint] process {} is not running; waiting to attach its hooks'.format(
                    process_name), file=sys.stderr)
                continue
            if target_pid is None:
                target_pid = process.pid
            attach_process(process_name, target_pid)
            if args.spawn and process_name == spawn_process_name and spawned_pid is not None:
                device.resume(spawned_pid)
        if not sessions and not pending_process_names:
            raise RuntimeError('No target processes were attached')
        if args.mitmproxy:
            print('[ready] synthetic flows will be sent through {}'.format(args.mitmproxy),
                  file=sys.stderr)
        while True:
            time.sleep(1)
            for process_name in list(pending_process_names):
                try:
                    process = device.get_process(process_name)
                except frida.ProcessNotFoundError:
                    continue
                try:
                    attach_process(process_name, process.pid)
                except frida.ProcessNotFoundError:
                    # The process can exit between enumeration and attach; keep watching.
                    continue
                pending_process_names.remove(process_name)
    except KeyboardInterrupt:
        print('\n[stop] detaching', file=sys.stderr)
    except frida.ProcessNotFoundError:
        print('Process {!r} was not found. Launch WeChat and confirm the process name with `frida-ps -U`.'.format(
            args.process), file=sys.stderr)
        return 2
    except Exception as error:
        print('[error] {}'.format(error), file=sys.stderr)
        return 1
    finally:
        output.close()
        print_summary()
        for script in scripts:
            try:
                script.unload()
            except Exception:
                pass
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
