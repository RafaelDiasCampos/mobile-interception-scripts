import Java from 'frida-java-bridge';

'use strict';

const CAPTURE_BUSINESS_CRYPTO = true;
const CAPTURE_UNPACK = true;
const CAPTURE_TRACE_EVENTS = true;
const pending = Object.create(null);
const configuredMmtlsHosts = Object.create(null);
const traceCounts = Object.create(null);
const classShapeCache = Object.create(null);
const activeStnCallbacks = Object.create(null);
const stnPendingRequests = Object.create(null);
const activeBcThreads = Object.create(null);
const lastUnpackByThread = Object.create(null);
let nextExchangeId = 0;
let nextBusinessCryptoCallId = 0;
const MAX_CRYPTO_BLOB_BYTES = 1024 * 1024;
const knownMmtlsHosts = Object.create(null);
[
  'long.weixin.qq.com',
  'short.weixin.qq.com',
  'extshort.weixin.qq.com',
  'findershort.weixin.qq.com',
  'minorshort.weixin.qq.com',
  'axshort.weixin.qq.com'
].forEach(function (host) { knownMmtlsHosts[host] = 'apk-mmtls-test-host-list'; });
knownMmtlsHosts['sgshort.wechat.com'] = 'observed-mmtls-shortlink-host';

function reportError(stage, error) {
  send({
    type: 'diagnostic',
    stage: stage,
    error: String(error)
  });
}

function normalizeHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
}

function routeInfo(host) {
  const normalized = normalizeHost(host);
  if (Object.prototype.hasOwnProperty.call(configuredMmtlsHosts, normalized)) {
    return {
      matched: true,
      source: 'runtime-MMStnManager-setMMTlsHostInfo',
      mode: configuredMmtlsHosts[normalized]
    };
  }
  if (Object.prototype.hasOwnProperty.call(knownMmtlsHosts, normalized)) {
    return {
      matched: true,
      source: knownMmtlsHosts[normalized],
      mode: knownMmtlsHosts[normalized] === 'apk-mmtls-test-host-list' ? 1 : null
    };
  }
  return { matched: false, source: 'not-observed', mode: null };
}

function safeString(fn, fallback) {
  try {
    const value = fn();
    return value === null || value === undefined ? (fallback || '') : String(value);
  } catch (_) {
    return fallback || '';
  }
}

function toBase64(bytes, AndroidBase64) {
  if (bytes === null || bytes === undefined) return '';
  const encoder = AndroidBase64.encodeToString.overload('[B', 'int');
  return String(encoder.call(AndroidBase64, bytes, 2)); // Base64.NO_WRAP
}

function observeConfiguredHosts(hosts, modes) {
  if (!hosts || !modes) return;
  for (let i = 0; i < hosts.length; i++) {
    const host = normalizeHost(hosts[i]);
    if (host) configuredMmtlsHosts[host] = Number(modes[i]);
  }
}

function traceHit(hookName, signature, details) {
  if (!CAPTURE_TRACE_EVENTS) return;
  const key = hookName + (signature ? ' ' + signature : '');
  const count = traceCounts[key] = (traceCounts[key] || 0) + 1;
  if (count <= 5 || count % 100 === 0) {
    send({
      type: 'trace', hook: hookName, signature: signature || '',
      hit_count: count, details: details || {}
    });
  }
}

function describeObject(object) {
  if (object === null || object === undefined) return { class_name: 'null' };
  try {
    const clazz = object.getClass();
    const className = String(clazz.getName());
    if (classShapeCache[className]) return classShapeCache[className];
    const shape = { class_name: className, fields: [], methods: [] };
    const fields = clazz.getDeclaredFields();
    for (let i = 0; i < fields.length && shape.fields.length < 20; i++) {
      shape.fields.push(String(fields[i].getName()) + ':' + String(fields[i].getType().getName()));
    }
    const methods = clazz.getDeclaredMethods();
    for (let i = 0; i < methods.length && shape.methods.length < 30; i++) {
      const name = String(methods[i].getName());
      if (/proto|request|buffer|serial|pack|encode|data|body|response|req|resp/i.test(name)) {
        shape.methods.push(name);
      }
    }
    classShapeCache[className] = shape;
    return shape;
  } catch (error) {
    return { class_name: '?', inspect_error: String(error) };
  }
}

function isHostname(value) {
  const normalized = normalizeHost(value);
  return normalized.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(normalized);
}

function callbackDetails(methodName, args) {
  const hostArg = normalizeHost(safeString(() => args[2], ''));
  const arg6 = safeString(() => args[6], '');
  const host = isHostname(hostArg) ? hostArg :
    (methodName === 'req2Buf' && isHostname(arg6) ? normalizeHost(arg6) : '');
  const details = {
    task_id: safeString(() => args[0], ''),
    host: host,
    debug_info: methodName === 'req2Buf' ? arg6 : '',
    channel: safeString(() => args[5], ''),
    mmtls_route: routeInfo(host),
    context: describeObject(args[1])
  };
  if (methodName === 'req2Buf') {
    details.output_buffer_size = safeString(() => args[3].size(), '?');
  } else if (methodName === 'buf2Resp') {
    details.input_buffer_size = safeString(() => args[3].length, '?');
  }
  return details;
}

function markActivePayloadHook(Thread, kind) {
  const threadId = String(Thread.currentThread().getId());
  const context = activeStnCallbacks[threadId];
  if (context) context.payloadHookSeen = true;
}

function captureStnCallbackBuffer(methodName, args, context, AndroidBase64) {
  const taskId = context.task_id;
  const pendingKey = taskId;
  if (methodName === 'req2Buf' && !context.payloadHookSeen) {
    const stream = args[3];
    const bytes = stream === null ? null : stream.toByteArray();
    const uri = context.debug_info && context.debug_info.charAt(0) === '/'
      ? context.debug_info : '';
    stnPendingRequests[pendingKey] = {
      id: context.id,
      task_id: taskId,
      host: context.host,
      uri: uri,
      debug_info: context.debug_info,
      mmtls_route: routeInfo(context.host)
    };
    send({
      type: 'request',
      id: context.id,
      task_id: taskId,
      host: context.host,
      uri: uri,
      debug_info: context.debug_info,
      mmtls_route: routeInfo(context.host),
      transport: 'wechat-mars-stn',
      capture_layer: 'stn-callback-buffer',
      data_stage: 'req2Buf output before native transport',
      request_content_type: 'application/octet-stream',
      request_body_b64: toBase64(bytes, AndroidBase64)
    });
  } else if (methodName === 'buf2Resp' && !context.payloadHookSeen) {
    const saved = stnPendingRequests[pendingKey] || {};
    const bytes = args[3];
    send({
      type: 'response',
      id: saved.id || context.id,
      task_id: taskId,
      host: context.host || saved.host || '',
      uri: saved.uri || '',
      debug_info: saved.debug_info || context.debug_info || '',
      mmtls_route: saved.mmtls_route || routeInfo(context.host),
      transport: 'wechat-mars-stn',
      capture_layer: 'stn-callback-buffer',
      data_stage: 'buf2Resp input after native transport',
      response_content_type: 'application/octet-stream',
      response_body_b64: toBase64(bytes, AndroidBase64),
      orphan_response: !Object.prototype.hasOwnProperty.call(stnPendingRequests, pendingKey)
    });
    delete stnPendingRequests[pendingKey];
  }
}

function arrayBufferView(value) {
  if (typeof ArrayBuffer === 'undefined') return null;
  try {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
  } catch (_) {}
  return null;
}

function byteArrayLength(value, ReflectArray) {
  const view = arrayBufferView(value);
  if (view !== null) return view.length;
  if (Array.isArray(value) || (value !== null && typeof value.length === 'number')) {
    return Math.max(0, Math.floor(Number(value.length)));
  }
  try {
    const getLength = ReflectArray.getLength.overload('java.lang.Object');
    return Number(getLength.call(ReflectArray, value));
  } catch (_) {
    return null;
  }
}

function byteArrayForEncoding(value, length, Java, ReflectArray) {
  const view = arrayBufferView(value);
  const values = new Array(length);
  if (view !== null) {
    for (let i = 0; i < length; i++) values[i] = view[i] > 127 ? view[i] - 256 : view[i];
    return Java.array('byte', values);
  }
  if (Array.isArray(value) || (value !== null && typeof value.length === 'number')) {
    for (let i = 0; i < length; i++) {
      const byte = Number(value[i]) & 0xff;
      values[i] = byte > 127 ? byte - 256 : byte;
    }
    return Java.array('byte', values);
  }

  const getByte = ReflectArray.getByte.overload('java.lang.Object', 'int');
  for (let i = 0; i < length; i++) {
    const byte = Number(getByte.call(ReflectArray, value, i)) & 0xff;
    values[i] = byte > 127 ? byte - 256 : byte;
  }
  return Java.array('byte', values);
}

function snapshotByteArray(value, Java, AndroidBase64, ReflectArray) {
  const length = byteArrayLength(value, ReflectArray);
  if (length === null || typeof length !== 'number' || isNaN(length) || !isFinite(length)) {
    return { class_name: '[B', length: null, base64: '', truncated: false,
      snapshot_error: 'could not determine Java byte array length' };
  }
  const result = {
    class_name: '[B', length: length,
    base64: '', truncated: length > MAX_CRYPTO_BLOB_BYTES
  };
  if (result.truncated) return result;

  try {
    try {
      result.base64 = toBase64(value, AndroidBase64);
    } catch (_) {
      result.base64 = toBase64(
        byteArrayForEncoding(value, length, Java, ReflectArray), AndroidBase64);
    }
  } catch (error) {
    result.snapshot_error = String(error);
  }
  return result;
}

function runtimeClassName(value) {
  try {
    if (typeof value.$className === 'string') return value.$className;
  } catch (_) {}
  try {
    const getClass = value.getClass;
    if (typeof getClass === 'function') return String(getClass.call(value).getName());
  } catch (_) {}
  return '';
}

function snapshotJavaValue(value, Java, AndroidBase64, ReflectArray, depth, typeHint) {
  if (value === null || value === undefined) return null;
  if (typeHint === '[B') return snapshotByteArray(value, Java, AndroidBase64, ReflectArray);
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return { value: String(value) };
  }
  if (arrayBufferView(value) !== null || Array.isArray(value)) {
    return snapshotByteArray(value, Java, AndroidBase64, ReflectArray);
  }
  try {
    const className = runtimeClassName(value) || '?';
    if (className === '[B') return snapshotByteArray(value, Java, AndroidBase64, ReflectArray);
    if (className === 'java.lang.String') {
      const str = String(value.toString());
      return { class_name: className, value: str.length <= 2048 ? str : str.slice(0, 2048), truncated: str.length > 2048 };
    }
    if (className === 'java.io.ByteArrayOutputStream') {
      const bytes = value.toByteArray();
      return snapshotJavaValue(bytes, Java, AndroidBase64, ReflectArray, depth + 1, '[B');
    }
    if (/^java\.lang\.(Boolean|Byte|Short|Integer|Long|Float|Double)$/.test(className)) {
      return { class_name: className, value: String(value.toString()) };
    }
    if (depth >= 2) return { class_name: className };

    const result = { class_name: className, fields: {} };
    const fields = value.getClass().getDeclaredFields();
    for (let i = 0; i < fields.length && i < 16; i++) {
      const field = fields[i];
      const name = String(field.getName());
      if (!/value|data|buffer|bytes|body|request|response|payload|array|length|size/i.test(name)) continue;
      try {
        if ((Number(field.getModifiers()) & 8) !== 0) continue;
        field.setAccessible(true);
        const fieldValue = field.get(value);
        const typeName = String(field.getType().getName());
        if (typeName === '[B' || /ByteArrayOutputStream/.test(typeName)) {
          result.fields[name] = snapshotJavaValue(
            fieldValue, Java, AndroidBase64, ReflectArray, depth + 1, typeName);
        } else if (/^(boolean|byte|short|int|long|float|double)$/.test(typeName) || typeName === 'java.lang.String') {
          result.fields[name] = fieldValue === null ? null : String(fieldValue.toString()).slice(0, 2048);
        }
      } catch (_) {}
    }
    return result;
  } catch (error) {
    return { class_name: '?', snapshot_error: String(error) };
  }
}

function snapshotArguments(args, argumentTypes, Java, AndroidBase64, ReflectArray) {
  return args.map(function (value, index) {
    const typeHint = argumentTypes[index] ? argumentTypes[index].className : '';
    return snapshotJavaValue(value, Java, AndroidBase64, ReflectArray, 0, typeHint);
  });
}

function byteArraySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return null;
  if (snapshot.class_name === '[B') return snapshot;
  const fields = snapshot.fields || {};
  const value = fields.value;
  if (value && value.class_name === '[B') return value;
  return null;
}

function installBusinessCryptoHooks(Java, AndroidBase64, ReflectArray, Thread) {
  const className = 'com.tencent.mm.protocal.MMProtocalJni';
  let clazz;
  try {
    clazz = Java.use(className);
  } catch (error) {
    send({ type: 'diagnostic', stage: 'business-crypto-class', error: String(error) });
    return [];
  }

  const installed = [];
  const methodNames = CAPTURE_BUSINESS_CRYPTO
    ? ['pack', 'packHybrid', 'packHybridEcdh', 'unpack']
    : (CAPTURE_UNPACK ? ['unpack'] : []);
  methodNames.forEach(function (methodName) {
    try {
      const method = clazz[methodName];
      if (!method || !method.overloads || method.overloads.length === 0) return;
      method.overloads.forEach(function (overload) {
        const original = overload;
        const signature = '(' + overload.argumentTypes.map(function (t) {
          return t.className;
        }).join(',') + ')';
        original.implementation = function () {
          const args = Array.prototype.slice.call(arguments);
          const callId = 'biz-' + Process.id + '-' + (++nextBusinessCryptoCallId);
          let before = [];
          if (CAPTURE_BUSINESS_CRYPTO) {
            try {
              before = snapshotArguments(args, overload.argumentTypes, Java, AndroidBase64, ReflectArray);
            } catch (error) {
              reportError('business-crypto-snapshot-before-' + methodName, error);
            }
          }
          let result;
          try {
            result = original.call(this, ...args);
          } catch (error) {
            send({
              type: 'business_crypto', call_id: callId, process_id: Process.id,
              thread_id: String(Thread.currentThread().getId()), timestamp_ms: Date.now(),
              class_name: className, method: methodName, signature: signature,
              args_before: before, outcome: 'throw', error: String(error)
            });
            throw error;
          }
          try {
            const after = CAPTURE_BUSINESS_CRYPTO
              ? snapshotArguments(args, overload.argumentTypes, Java, AndroidBase64, ReflectArray)
              : [snapshotJavaValue(args[0], Java, AndroidBase64, ReflectArray, 0,
                overload.argumentTypes[0] ? overload.argumentTypes[0].className : '')];
            const threadId = String(Thread.currentThread().getId());
            let correlatedToBc = false;
            if (methodName === 'unpack' && activeBcThreads[threadId]) {
              const output = byteArraySnapshot(after[0]);
              if (output && output.base64 && Number(output.length) > 0) {
                lastUnpackByThread[threadId] = {
                  call_id: callId,
                  bytes_base64: output.base64,
                  length: Number(output.length)
                };
                correlatedToBc = true;
              }
            }
            send({
              type: 'business_crypto', call_id: callId, process_id: Process.id,
              thread_id: threadId, timestamp_ms: Date.now(),
              class_name: className, method: methodName, signature: signature,
              args_before: before,
              args_after: after,
              correlated_to_bc: correlatedToBc,
              result: snapshotJavaValue(result, Java, AndroidBase64, ReflectArray, 0,
                overload.returnType ? overload.returnType.className : ''),
              outcome: 'return'
            });
          } catch (error) {
            reportError('business-crypto-' + methodName, error);
          }
          return result;
        };
        installed.push(methodName + signature);
      });
    } catch (error) {
      reportError('install-business-crypto-' + methodName, error);
    }
  });

  send({ type: 'status', message: 'business-layer pack/unpack hooks installed', hooks: installed });
  return installed;
}

function installTraceHooks(Java, className, methodName, Thread, AndroidBase64) {
  try {
    const clazz = Java.use(className);
    const method = clazz[methodName];
    if (!method || !method.overloads) {
      send({ type: 'diagnostic', stage: 'trace-hook-' + methodName, error: 'method not found' });
      return false;
    }
    method.overloads.forEach(function (overload) {
      const original = overload;
      const signature = '(' + overload.argumentTypes.map(function (t) {
        return t.className;
      }).join(',') + ')';
      original.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        const threadId = String(Thread.currentThread().getId());
        const previousContext = activeStnCallbacks[threadId];
        const details = callbackDetails(methodName, args);
        const context = {
          task_id: details.task_id,
          host: details.host,
          debug_info: details.debug_info,
          id: 'stn-' + details.task_id + '-' + Date.now() + '-' + (++nextExchangeId),
          payloadHookSeen: false
        };
        activeStnCallbacks[threadId] = context;
        try {
          const result = original.call(this, ...args);
          if (methodName === 'req2Buf') {
            details.output_buffer_size = safeString(() => args[3].size(), '?');
          } else if (methodName === 'buf2Resp') {
            details.input_buffer_size = safeString(() => args[3].length, '?');
          }
          traceHit(className + '.' + methodName, signature, details);
          captureStnCallbackBuffer(methodName, args, context, AndroidBase64);
          return result;
        } finally {
          if (previousContext) activeStnCallbacks[threadId] = previousContext;
          else delete activeStnCallbacks[threadId];
        }
      };
    });
    return true;
  } catch (error) {
    reportError('install-trace-' + methodName, error);
    return false;
  }
}

Java.perform(function () {
  const System = Java.use('java.lang.System');
  const AndroidBase64 = Java.use('android.util.Base64');
  const ReflectArray = Java.use('java.lang.reflect.Array');
  const V2 = Java.use('com.tencent.mm.modelbase.v2');
  const R2 = Java.use('com.tencent.mm.modelbase.r2');
  const RequestProto = Java.use('ra5.ah');
  const Thread = Java.use('java.lang.Thread');
  const traceHooks = [];
  const businessCryptoHooks = CAPTURE_BUSINESS_CRYPTO
    ? installBusinessCryptoHooks(Java, AndroidBase64, ReflectArray, Thread) : [];

  try {
    const StnManager = Java.use('com.tencent.mars.mm.MMStnManager');
    const setHosts = StnManager.setMMTlsHostInfo.overload('[Ljava.lang.String;', '[I');
    setHosts.implementation = function (hosts, modes) {
      try {
        observeConfiguredHosts(hosts, modes);
      } catch (error) {
        reportError('mmtls-host-map', error);
      }
      return setHosts.call(this, hosts, modes);
    };
  } catch (error) {
    reportError('install-mmtls-host-map-hook', error);
  }

  const o8 = V2.O8.overload(
    'int', '[B', 'java.lang.String', 'int', 'int', 'int', 'int',
    '[B', '[B', '[B', 'int', 'boolean', '[B', 'boolean', 'int',
    'boolean', 'boolean', 'boolean'
  );
  o8.implementation = function () {
    const args = Array.prototype.slice.call(arguments);
    traceHit('com.tencent.mm.modelbase.v2.O8');
    const key = String(System.identityHashCode(this));
    try {
      const requestHost = String(args[2] || '');
      const uri = safeString(() => this.d.value.getUri(), '');
      const r2 = Java.cast(this.f.value, R2);
      const proto = Java.cast(r2.g.value, RequestProto);
      const requestBytes = proto.toProtoBuf();
      pending[key] = {
        id: Date.now() + '-' + (++nextExchangeId),
        timestamp_ms: Date.now(),
        host: requestHost,
        uri: uri,
        mmtls_route: routeInfo(requestHost),
        request_body_b64: toBase64(requestBytes, AndroidBase64)
      };
      send({
        type: 'request',
        id: pending[key].id,
        timestamp_ms: pending[key].timestamp_ms,
        host: pending[key].host,
        uri: pending[key].uri,
        mmtls_route: pending[key].mmtls_route,
        transport: 'wechat-mars-stn',
        request_content_type: 'application/x-protobuf',
        request_body_b64: pending[key].request_body_b64
      });
      markActivePayloadHook(Thread, 'request');
    } catch (error) {
      reportError('capture-request', error);
    }
    return o8.call(this, ...args);
  };

  const bc = V2.bc.overload('int', '[B');
  bc.implementation = function (resultCode, encryptedOrPackedBytes) {
    traceHit('com.tencent.mm.modelbase.v2.bc');
    const key = String(System.identityHashCode(this));
    const threadId = String(Thread.currentThread().getId());
    delete lastUnpackByThread[threadId];
    activeBcThreads[threadId] = true;
    let result;
    try {
      result = bc.call(this, resultCode, encryptedOrPackedBytes);
    } catch (error) {
      delete activeBcThreads[threadId];
      delete lastUnpackByThread[threadId];
      throw error;
    }
    delete activeBcThreads[threadId];
    const unpacked = lastUnpackByThread[threadId] || null;
    delete lastUnpackByThread[threadId];
    try {
      const saved = pending[key] || {};
      const responseBytes = result === null ? null : result.d.value;
      const wrapperBodyB64 = toBase64(responseBytes, AndroidBase64);
      const responseUri = result === null ? '' : safeString(() => result.o.value, '');
      const responsePayload = {
        type: 'response',
        id: saved.id || Date.now() + '-' + (++nextExchangeId),
        timestamp_ms: Date.now(),
        thread_id: threadId,
        host: saved.host || '',
        uri: responseUri || saved.uri || '',
        mmtls_route: saved.mmtls_route || routeInfo(saved.host || ''),
        transport: 'wechat-mars-stn',
        request_content_type: 'application/x-protobuf',
        response_content_type: 'application/x-protobuf',
        request_body_b64: saved.request_body_b64 || '',
        response_body_b64: unpacked ? unpacked.bytes_base64 : wrapperBodyB64,
        response_body_stage: unpacked
          ? 'MMProtocalJni.unpack output after business decryption'
          : 'V2.bc result.d.value; unpack output unavailable',
        app_result_code: Number(resultCode),
        orphan_response: !Object.prototype.hasOwnProperty.call(pending, key)
      };
      if (unpacked) {
        responsePayload.response_wrapper_body_b64 = wrapperBodyB64;
        responsePayload.unpack_call_id = unpacked.call_id;
        responsePayload.unpack_length_bytes = unpacked.length;
      }
      send(responsePayload);
      markActivePayloadHook(Thread, 'response');
      delete pending[key];
    } catch (error) {
      reportError('capture-response', error);
    }
    return result;
  };

  traceHooks.push(installTraceHooks(
    Java, 'com.tencent.mars.mm.MMStnManagerCallback', 'req2Buf', Thread, AndroidBase64));
  traceHooks.push(installTraceHooks(
    Java, 'com.tencent.mars.mm.MMStnManagerCallback', 'buf2Resp', Thread, AndroidBase64));

  send({
    type: 'status',
    message: 'WeChat Mars/STN capture hooks installed',
    process_scope: 'current-process',
    business_crypto_enabled: CAPTURE_BUSINESS_CRYPTO || CAPTURE_UNPACK,
    known_mmtls_hosts: Object.keys(knownMmtlsHosts),
    mars_callback_trace_hooks: traceHooks,
    business_crypto_hooks: businessCryptoHooks,
    business_crypto_mode: CAPTURE_BUSINESS_CRYPTO ? 'all' :
      (CAPTURE_UNPACK ? 'unpack' : 'off')
  });
});
