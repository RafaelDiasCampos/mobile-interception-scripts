# Mobile Interception Scripts

This repository contains Frida scripts to help intercept HTTPS traffic from selected Android and iOS applications. They were developed for the research project **Mobile Devices and Data Privacy: Assessing Data Leakage in Android and iOS Applications**.

## Analyzed applications

These are the application identifiers and versions documented for the builds used in the analysis. Some of the scripts hook into specific library offsets, so are unlikely to work with different versions of these applications.

| App | Platform | Package or bundle ID | Version |
| --- | --- | --- | --- |
| AliExpress | iOS | `com.alibaba.iAliexpress` | `8.176.0` |
| Facebook | Android | `com.facebook.katana` | `580.0.0.51.74` |
| Facebook | iOS | `com.facebook.Facebook` | `580.0.0` |
| Instagram | Android | `com.instagram.android` | `449.0.0.52.84` |
| Instagram | iOS | `com.burbn.instagram` | `448.0.0` |
| TikTok | iOS | `com.zhiliaoapp.musically` | `47.0.0` |
| WeChat | Android | `com.tencent.mm` | `8.0.77` |
| WeChat | iOS | `com.tencent.xin` | `8.0.78` |
| WhatsApp | Android | `com.whatsapp` | `2.26.38.73` |
| WhatsApp | iOS | `net.whatsapp.WhatsApp` | `26.38.74` |

## Requirements

- A device with Frida access and a matching host-side Frida installation. The standalone `.js` files are loaded with the Frida CLI; the Python drivers require the `frida` Python package.
- Python 3 for capture drivers. Install `mitmproxy` when using a `*_mitmproxy.py` addon.
- `WeChat/Android/mmtls_hook.js` imports `frida-java-bridge`. Its driver requires `frida-compile` and bundles the hook before loading it. Install the bridge in `WeChat/Android/` if it is not already present there.

## Standalone Frida hooks

From this directory, use the same calling pattern for each standalone hook:

```sh
frida -U -f <bundle-or-package-id> -l <App>/<Platform>/<script>.js
```

Available hooks are:

- `AliExpress/iOS/tls_unpin.js`
- `Facebook/Android/tls_unpin.js` and `Facebook/iOS/tls_unpin.js`
- `Instagram/Android/tls_unpin.js` and `Instagram/iOS/tls_unpin.js`
- `TikTok/iOS/tls_unpin.js`

For example, load Instagram iOS with:

```sh
frida -U -f com.burbn.instagram -l Instagram/iOS/tls_unpin.js
```

That hook has `autoStart: false`; resume the app and call `start()` in the Frida REPL to install its selected hook groups. The other standalone scripts keep their own startup behavior and configuration constants. `WhatsApp/iOS/plaintext_log.js` writes to the Frida console; it is separate from the iOS capture driver below.

## WeChat capture

The Android and iOS drivers load their adjacent `mmtls_hook.js` files and can forward captures through the shared `WeChat/mmtls_mitmproxy.py` addon. Start mitmproxy first:

```sh
mitmdump --listen-port 8080 --set connection_strategy=lazy -s WeChat/mmtls_mitmproxy.py
```

Then run the driver for the target platform:

```sh
python3 WeChat/Android/mmtls_capture.py --mitmproxy http://127.0.0.1:8080
# or
python3 WeChat/iOS/mmtls_capture.py --mitmproxy http://127.0.0.1:8080
```

The addon handles Android request/response exchanges and iOS request snapshots on separate capture paths. Both drivers write JSON Lines output; use `--output` to change its path, `--hook` to load a different agent, or `--help` for other options. In mitmproxy, `--set wechat_ios_view=json` shows a schema-free wire preview instead of raw request bytes.

## WhatsApp plaintext capture

The Android and iOS drivers load their adjacent `plaintext_hook.js` files and forward captures through the shared `WhatsApp/plaintext_mitmproxy.py` addon. Start mitmproxy first:

```sh
mitmdump --listen-port 8080 --set connection_strategy=lazy -s WhatsApp/plaintext_mitmproxy.py
```

Then run the driver for the target platform:

```sh
python3 WhatsApp/Android/plaintext_capture.py --proxy http://127.0.0.1:8080
# or
python3 WhatsApp/iOS/plaintext_capture.py --proxy http://127.0.0.1:8080
```

Both drivers send captures to `whatsapp-debug.invalid` through the local proxy. Use `--jsonl` to save a local copy, `--attach` for a running app, `--hook` to load a different agent, or `--test` to check the addon without a device. The iOS driver also supports `--source` to select `query`, `aes`, or `both`.