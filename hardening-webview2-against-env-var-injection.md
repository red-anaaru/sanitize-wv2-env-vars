# Hardening WebView2 Apps Against Environment-Variable Injection

> A drop-in mitigation for an attack any local user can run with **no admin rights**, on any WebView2-based app on Windows (and macOS, for the preview SDK).
>
> **One-liner:** WebView2 reads several `WEBVIEW2_*` env vars at startup and applies them as overrides to whatever your app passed to `CreateCoreWebView2EnvironmentWithOptions`. An attacker who can write to the user's environment block can flip on Chrome DevTools Protocol against your WebView and steal the user's session. The fix: clear those env vars in your process *before* anything WebView2-related runs. Code in [`webview2-env-sanitizer-sample/`](./webview2-env-sanitizer-sample), MIT-0.

---

## What goes wrong if you do nothing

A user-level attacker — local malware, a malicious previously-installed app, anything running as the same user — can do *all* of the following to your app, the next time the user launches it:

- **Steal cookies** from your origin, including `httpOnly` ones → session hijack.
- **Run arbitrary JavaScript** in your origin → reads/writes anything the page can see.
- **Capture screenshots** of WebView contents.
- **Read the DOM** even if your UI never displays parts of it.
- **Redirect the user-data folder** → permanent attacker access to credentials, history, IndexedDB, service-worker storage.
- **Swap in a different WebView2 binary** → effectively code execution inside your signed process.

No admin. No UAC. No prior code execution beyond writing one string to the user's own environment block:

```powershell
[Environment]::SetEnvironmentVariable(
    'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS',
    '--remote-debugging-port=9222 --remote-allow-origins=*',
    'User')
```

Persists across reboots in `HKCU\Environment`. Next launch:

```powershell
Invoke-RestMethod http://127.0.0.1:9222/json
# Returns the list of WebView2 targets in your app.
# From there: full Chrome DevTools Protocol over the WebSocket URL.
#   Network.getAllCookies     → bypasses httpOnly
#   Runtime.evaluate          → arbitrary JS in your origin
#   Page.captureScreenshot, DOM.getDocument, Input.dispatchKeyEvent, …
```

The attacker now has the user's session inside your app.

---

## Why this is possible

WebView2 deliberately honors a set of `WEBVIEW2_*` environment variables and treats them as overrides for the options your code passes. From the [Win32 IDL reference](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl):

> The `browserExecutableFolder`, `channelSearchKind`, `releaseChannels`, `userDataFolder` and `additionalBrowserArguments` of the `environmentOptions` may be overridden by values either specified in environment variables or in the registry. […] If `additionalBrowserArguments` is specified in environment variable or in the registry, it is **appended** to the corresponding values in `CreateCoreWebView2EnvironmentWithOptions` parameters.

There is no API switch, manifest knob, or `CoreWebView2` setting that disables env-var overrides. If your code does nothing, the runtime obeys the env block.

The full set of env vars the runtime reads:

| Variable | What an attacker gains | Effect |
|---|---|---|
| `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` | Adds Chromium CLI flags: enable CDP, disable sandbox, load extensions, disable web security | **Appended** |
| `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` | Loads a different (attacker-controlled) WebView2 binary | **Replaces** |
| `WEBVIEW2_USER_DATA_FOLDER` | Redirects cookie/profile storage to a path the attacker can read | **Replaces** |
| `WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER` | Attaches a script debugger over a named pipe | Honored |
| `WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER` | Forces the runtime to pause on launch waiting for a debugger | Honored |
| `WEBVIEW2_CHANNEL_SEARCH_KIND` | Forces a different channel (Beta/Dev/Canary) of the WebView2 runtime | **Replaces** |
| `WEBVIEW2_RELEASE_CHANNELS` | Restricts/changes channel selection | **Replaces** |

The first three are the most damaging. The two channel vars are downgrade vectors — useful if a particular Chromium build has a known weakness. Microsoft's own IDL warns:

> If you set both `WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER` and `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` environment variables, the WebViews hosted in your app and associated contents may [be] exposed to 3rd party apps such as debuggers.

### Why your other defenses don't catch this

- **AppContainer / MSIX packaging:** Doesn't help. The env block lives in `HKCU` and is read by the WebView2 loader inside *your* process.
- **Code signing / WDAC / integrity policies:** The WebView2 runtime is signed by Microsoft. The attack uses it correctly — it just feeds it attacker-supplied flags.
- **macOS App Sandbox:** Strips `DYLD_*` env vars but **not** `WEBVIEW2_*`. A poisoned `~/.zshrc`, `launchctl setenv`, or LaunchAgent plist propagates straight in.
- **UAC / token boundaries:** The attacker is the same user the app runs as. There is no privilege boundary to cross.

---

## The fix

Clear every `WEBVIEW2_*` env var from your process *before* the WebView2 loader reads them. Two rules:

1. **Run early.** Before `CreateCoreWebView2EnvironmentWithOptions` (Win32), `CoreWebView2Environment.CreateAsync` (.NET / WinUI), or `[MSWebView2Environment createWithOptions:]` (macOS preview). The first line of `wWinMain` / `Main` / `applicationDidFinishLaunching:` is the right place.
2. **Never throw.** This runs before logging, before COM init. A crash here means the app can't launch — strictly worse than skipping sanitization.

### The minimal C# version (drop-in for any .NET WebView2 app)

If you don't need scope detection or telemetry, this is the whole fix:

```csharp
static class WebView2Sanitizer {
    static readonly string[] Vars = {
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
        "WEBVIEW2_USER_DATA_FOLDER",
        "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
        "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
        "WEBVIEW2_CHANNEL_SEARCH_KIND",
        "WEBVIEW2_RELEASE_CHANNELS",
    };
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Sanitize() {
        foreach (var name in Vars) Environment.SetEnvironmentVariable(name, null);
    }
}
```

`[ModuleInitializer]` runs before `Main`, which is before any WebView2 type can be constructed. That's it for WPF / WinForms / WinUI 3 / MAUI.

### The C++ sample (with telemetry and scope detection)

The sample under [`webview2-env-sanitizer-sample/`](./webview2-env-sanitizer-sample) is C++17, STL only — no WIL, no Boost, only `<Windows.h>` on Windows. It builds as a static lib via the included `CMakeLists.txt`.

| File | Purpose |
|---|---|
| `webview2_env_sanitizer.hpp` | Public API + value-fingerprint constants |
| `webview2_env_sanitizer.cpp` | Platform-agnostic helpers |
| `webview2_env_sanitizer_win.cpp` | Windows: clears env vars, detects HKCU vs HKLM vs process-only origin |
| `webview2_env_sanitizer_mac.mm` | macOS: clears env vars via `unsetenv` |
| `main_example.cpp` | Where to call it |
| `CMakeLists.txt` | Builds it |

> **Note on coverage:** the current sample's `kDangerousEnvVars` array clears 5 of the 7 documented vars on Windows (it omits `WEBVIEW2_CHANNEL_SEARCH_KIND` and `WEBVIEW2_RELEASE_CHANNELS`) and 3 on macOS. Add the missing names to the arrays for full coverage; they're listed in the table above.

#### Public API

```cpp
namespace webview2_security {

struct SanitizeResult {
    std::vector<std::string> detected_vars;          // Vars that were cleared
    std::vector<std::string> detected_scopes;        // "user" | "machine" | "process_only" | "unknown"
    std::vector<uint32_t>    detected_fingerprints;  // See fingerprint:: constants
    std::vector<std::string> failed_vars;            // Clear failed (rare)

    bool any_detected() const noexcept;
};

[[nodiscard]] SanitizeResult SanitizeWebView2EnvironmentVariables() noexcept;

}  // namespace webview2_security
```

#### Where to call it (C++)

```cpp
int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();  // FIRST line
    // ... your usual init: CoInitialize, logging, CreateCoreWebView2EnvironmentWithOptions, ...
    if (sanitize.any_detected()) {
        // Once telemetry is up:
        ReportTelemetry("webview2_env_sanitization", sanitize);
    }
}
```

For .NET apps that prefer the structured-result version, wrap the static lib with a small C ABI and `[DllImport]` from `Main` (or a `[ModuleInitializer]`) before any `CoreWebView2Environment` is touched.

#### macOS (MSWebView2 preview SDK)

```objc
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();
    // ... [MSWebView2Environment createWithOptions:...] ...
}
```

If your macOS app has a **prewarm helper** binary that creates an `MSWebView2Environment` outside `AppDelegate` (a common startup-perf optimization), call the sanitizer at the top of *that* helper's `main()` too. Don't gate it on a feature flag in the helper — flags usually aren't loaded that early, and the prewarm path is the highest-risk one because it runs before any of your normal startup hooks.

### What the C++ implementation actually does

**Windows** (`webview2_env_sanitizer_win.cpp`):

1. For each `WEBVIEW2_*` name, calls `GetEnvironmentVariableW` to detect.
2. If present, computes a **scope tag** by reading the registry directly:
   - `"user"` → set in `HKCU\Environment`. Persistent attack on this user account. **High signal.**
   - `"machine"` → set in `HKLM\…\Session Manager\Environment`. Likely admin or GPO.
   - `"process_only"` → inherited from a parent process (often a launcher or IDE). Often legitimate dev work.
   - The scope is the single most useful piece of telemetry: a `"user"`-scope hit on `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` containing `--remote-debugging` is almost certainly an attack; a `"process_only"` hit is more likely a developer.
3. Computes a **value fingerprint** — a bitmask of which suspicious flags appear (`--remote-debugging`, `--user-data-dir`, `--load-extension`, `--no-sandbox`, `--disable-web-security`, other). The raw value is **never** stored or logged.
4. Calls `SetEnvironmentVariableW(name, nullptr)` to remove the variable from this process's environment block.
5. Verifies removal with a second read.

**macOS** (`webview2_env_sanitizer_mac.mm`):

1. Same flow with `getenv` / `unsetenv`.
2. Scope is currently `"unknown"` — distinguishing `launchctl setenv` vs `~/.zshrc` vs plist origin is doable but requires extra plumbing; the value fingerprint is usually enough.

The whole thing is wrapped in `try { … } catch (...) {}` and marked `noexcept`. If anything goes wrong, the app launches anyway with whatever clearing succeeded.

---

## Telemetry

The sample is intentionally telemetry-agnostic: it returns `SanitizeResult` and lets you feed it into whatever pipeline you use (App Insights, Sentry, OneDS, ETW, syslog).

- ✅ **Do** emit: var names, scope tags, fingerprint bitmasks, success/failure counts.
- ❌ **Do not** emit: the raw env var value. It can contain user paths, tokens, GUIDs, attacker-supplied content. The fingerprint exists precisely so you don't have to.

A starting Kusto query — assumes you log one row per detected var, or `mv-expand` first if you log them as parallel arrays:

```kusto
ClientEvents
| where EventName == "webview2_env_sanitization"
| mv-expand var = detected_vars to typeof(string),
            scope = detected_scopes to typeof(string),
            fp   = detected_fingerprints to typeof(long)
| where binary_and(fp, 1) != 0    // kRemoteDebugging bit
| where scope == "user"
| summarize attack_attempts = dcount(UserId), devices = dcount(DeviceId) by bin(Timestamp, 1d)
```

That gives you the rate of likely-real attack attempts vs. background noise from devs with `--user-data-dir` set in their shell.

## Rollout

If you ship to a large fleet, **gate the clearing on a feature flag for the first ring or two**. A non-zero number of internal devs and IT-managed populations rely on `WEBVIEW2_USER_DATA_FOLDER` for legitimate reasons (custom profile paths, kiosk configs, automation). The telemetry is exactly what you need to size that population *before* you flip the default to "block."

In prewarm/helper processes, **don't gate** — feature flags typically aren't loaded that early, and the security tradeoff (force-clear vs. occasional dev-tool breakage in a helper) lands on force-clear.

---

## Validating the fix

Reproduce the original attack and confirm CDP doesn't come up.

**Windows:**

```powershell
# 1. Set the bad var
[Environment]::SetEnvironmentVariable(
    'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS',
    '--remote-debugging-port=9222 --remote-allow-origins=*',
    'User')

# 2. Launch your app
Start-Process "yourapp:"

# 3. Confirm nothing is listening on 9222
Get-NetTCPConnection -State Listen -LocalPort 9222   # should return nothing
Invoke-RestMethod http://127.0.0.1:9222/json         # should fail to connect
```

**macOS:**

```bash
launchctl setenv WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS '--remote-debugging-port=9222 --remote-allow-origins=*'
open -a "YourApp"
lsof -iTCP:9222 -sTCP:LISTEN   # should be empty
```

---

## What this does NOT cover

- **Registry-based injection.** WebView2 also honors per-app override registry keys under `Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments\{AppId}`. The IDL says **both `HKLM` and `HKCU` are checked**, so a user-level attacker can persist via the registry without admin. Worse: if the runtime doesn't find an env-var override, it **falls through to the registry** — so an attacker who sets *both* paths survives env-var clearing. If your threat model includes registry tampering, also clear those keys (or detect them) at startup.
- **Compromised parent processes.** A malicious parent process can do far worse than set env vars. This is one layer.
- **Other Chromium-embedding runtimes.** CEF, Electron, .NET MAUI's Chromium-backed `BlazorWebView`, etc. have their own env-var stories. This code is WebView2-specific.

---

## Cost

Roughly 10 µs at startup. Zero runtime overhead afterwards. There is no good reason for a production WebView2 app *not* to do this.

## References

- [WebView2 Win32 IDL reference — `additionalBrowserArguments` and the `WEBVIEW2_*` env vars](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl)
- [WebView2 security best practices](https://learn.microsoft.com/microsoft-edge/webview2/concepts/security)
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)

**Code:** [`webview2-env-sanitizer-sample/`](./webview2-env-sanitizer-sample) — `webview2_env_sanitizer.{hpp,cpp}` + `_win.cpp` + `_mac.mm` + `CMakeLists.txt`. MIT-0.
