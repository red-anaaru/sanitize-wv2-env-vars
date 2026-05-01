# Hardening WebView2 Apps Against Startup-Time Argument Injection

> A drop-in mitigation for an attack any local user can run with **no admin rights**, on any WebView2-based app on Windows (and macOS, for the preview SDK).
>
> **One-liner:** WebView2 reads several `WEBVIEW2_*` env vars *and* a parallel set of per-app values under `HKCU\Software\Policies\Microsoft\Edge\WebView2\…` at startup, and applies them as overrides to whatever your app passed to `CreateCoreWebView2EnvironmentWithOptions`. Either channel lets an attacker flip on Chrome DevTools Protocol against your WebView and steal the user's session. The fix: clear the env vars *and* inspect/clean the policy registry overrides in your process *before* anything WebView2-related runs. Code in [`src/`](./src), MIT-0.

---

## What goes wrong if you do nothing

A user-level attacker — local malware, a malicious previously-installed app, anything running as the same user — can do *all* of the following to your app, the next time the user launches it:

- **Steal cookies** from your origin, including `httpOnly` ones → session hijack.
- **Run arbitrary JavaScript** in your origin → reads/writes anything the page can see.
- **Capture screenshots** of WebView contents.
- **Read the DOM** even if your UI never displays parts of it.
- **Redirect the user-data folder** → permanent attacker access to credentials, history, IndexedDB, service-worker storage.
- **Swap in a different WebView2 binary** → effectively code execution inside your signed process.

No admin. No UAC. No prior code execution beyond writing **either** of the following — each is enough on its own:

```powershell
# Channel 1 — environment variable, persisted in HKCU\Environment
[Environment]::SetEnvironmentVariable(
    'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS',
    '--remote-debugging-port=9222 --remote-allow-origins=*',
    'User')
```

```powershell
# Channel 2 — per-app policy registry override (no admin needed for HKCU)
$key = 'HKCU:\Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'yourapp.exe' `
    -Value '--remote-debugging-port=9222 --remote-allow-origins=*' `
    -PropertyType String -Force | Out-Null
```

Both persist across reboots. Next launch:

```powershell
Invoke-RestMethod http://127.0.0.1:9222/json
# Returns the list of WebView2 targets in your app.
# From there: full Chrome DevTools Protocol over the WebSocket URL.
#   Network.getAllCookies     → bypasses httpOnly
#   Runtime.evaluate          → arbitrary JS in your origin
#   Page.captureScreenshot, DOM.getDocument, Input.dispatchKeyEvent, …
```

The attacker now has the user's session inside your app. **Clearing only the env vars is not a complete fix:** when the env var is absent, the WebView2 runtime falls through to the registry. An attacker who plants the registry value alone — or sets both, knowing your code only handles the env var — bypasses env-var-only sanitization entirely.

---

## Why this is possible

WebView2 deliberately honors a set of `WEBVIEW2_*` environment variables **and** a parallel set of per-app registry values, and treats both as overrides for the options your code passes. From the [Win32 IDL reference](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl):

> The `browserExecutableFolder`, `channelSearchKind`, `releaseChannels`, `userDataFolder` and `additionalBrowserArguments` of the `environmentOptions` may be overridden by values either specified in environment variables **or in the registry**. […] If `additionalBrowserArguments` is specified in environment variable or in the registry, it is **appended** to the corresponding values in `CreateCoreWebView2EnvironmentWithOptions` parameters.

> If none of those environment variables exist, then **the registry is examined next**. […] First verify with Root as `HKLM` and then `HKCU`. `AppId` is first set to the Application User Model ID of the process, then if no corresponding registry key, the `AppId` is set to the compiled code name of the process, or if that is not a registry key then `*`.

There is no API switch, manifest knob, or `CoreWebView2` setting that disables either set of overrides. If your code does nothing, the runtime obeys both — env block first, then registry.

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

### The parallel registry channel

WebView2 exposes the same overrides under `Software\Policies\Microsoft\Edge\WebView2\…`, in **both `HKLM` and `HKCU`**:

| Subkey | Value name | What it does |
|---|---|---|
| `\AdditionalBrowserArguments` | `<exe-leaf>` *or* `*` | Appends Chromium switches (CDP, sandbox flags, …) — the registry analog of `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` |
| `\BrowserExecutableFolder` | `<exe-leaf>` *or* `*` | Replaces the WebView2 binary path |
| `\UserDataFolder` | `<exe-leaf>` *or* `*` | Replaces the profile path |
| `\ChannelSearchKind`, `\ReleaseChannels` | `<exe-leaf>` *or* `*` | Channel-selection overrides |

Two things make this worse than the env-var channel:

1. **HKCU is user-writable.** A non-admin attacker can persist there. HKLM requires admin, but the runtime still reads it — useful as a forensic signal.
2. **It's a fall-through.** When the env var is missing, the runtime walks the registry. So an attacker who sets *only* the registry value, or who sets both, survives any sanitization that touches only the env block.

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

If you don't need scope detection or telemetry, **and you accept that this only closes the env-var channel** (see below for the registry channel):

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
        // Registry layer — see below. Without this, an attacker who sets
        // HKCU\Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments\<exe>
        // bypasses everything above.
        TryCleanPolicyRegistry();
    }

    static void TryCleanPolicyRegistry() {
        const string subkey = @"Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments";
        string exe = System.IO.Path.GetFileName(
            System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "");
        try {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(subkey, writable: true);
            if (k == null) return;
            foreach (var name in new[] { exe, "*" }) {
                if (string.IsNullOrEmpty(name)) continue;
                if (k.GetValue(name) is string v &&
                    (v.Contains("--remote-debugging") || v.Contains("--load-extension") ||
                     v.Contains("--no-sandbox") || v.Contains("--disable-web-security"))) {
                    k.DeleteValue(name, throwOnMissingValue: false);
                }
            }
        } catch { /* best-effort */ }
    }
}
```

`[ModuleInitializer]` runs before `Main`, which is before any WebView2 type can be constructed. That's it for WPF / WinForms / WinUI 3 / MAUI.

### The C++ sample (with telemetry and scope detection)

The sample under [`src/`](./src) is C++17, STL only — no WIL, no Boost, only `<Windows.h>` on Windows. It builds as a static lib via the included `CMakeLists.txt`.

| File | Purpose |
|---|---|
| `webview2_env_sanitizer.hpp` | Public API + value-fingerprint constants |
| `webview2_env_sanitizer.cpp` | Platform-agnostic helpers |
| `webview2_env_sanitizer_win.cpp` | Windows: clears all 7 env vars (HKCU/HKLM/process-only scope tagged); inspects per-app policy registry overrides under HKCU+HKLM and deletes attack-token-bearing HKCU values |
| `webview2_env_sanitizer_mac.mm` | macOS: clears the 3 vars the MSWebView2 preview honors (the Windows-only script-debugger, channel-selection, and registry vectors don't apply) via `unsetenv` |
| `main_example.cpp` | Where to call it |
| `CMakeLists.txt` | Builds it |

#### Public API

```cpp
namespace webview2_security {

struct SanitizeResult {
    // Env-var layer.
    std::vector<std::string> detected_vars;           // Names that were cleared
    std::vector<std::string> detected_scopes;         // "user" | "machine" | "process_only" | "unknown"
    std::vector<uint32_t>    detected_fingerprints;   // See fingerprint:: constants
    std::vector<std::string> failed_vars;             // Clear failed (rare)

    // Policy-registry layer (Windows).
    std::vector<std::string> detected_policy_hives;        // "HKCU" | "HKLM"
    std::vector<std::string> detected_policy_value_names;  // "<exe-leaf>" | "*"
    std::vector<uint32_t>    detected_policy_fingerprints; // Same fingerprint:: bitmask
    std::vector<std::string> policy_keys_cleared;          // "HKCU:<value-name>" — actually deleted
    std::vector<std::string> policy_keys_failed;           // "HKCU:<value-name>" — delete attempted, failed

    bool any_detected() const noexcept;  // true if either layer found something
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

**Windows** (`webview2_env_sanitizer_win.cpp`) — two layers:

*Layer 1 — environment variables:*

1. For each `WEBVIEW2_*` name, calls `GetEnvironmentVariableW` to detect.
2. If present, computes a **scope tag** by reading the registry directly:
   - `"user"` → set in `HKCU\Environment`. Persistent attack on this user account. **High signal.**
   - `"machine"` → set in `HKLM\…\Session Manager\Environment`. Likely admin or GPO.
   - `"process_only"` → inherited from a parent process (often a launcher or IDE). Often legitimate dev work.
   - The scope is the single most useful piece of telemetry: a `"user"`-scope hit on `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` containing `--remote-debugging` is almost certainly an attack; a `"process_only"` hit is more likely a developer.
3. Computes a **value fingerprint** — a bitmask of which suspicious flags appear (`--remote-debugging`, `--user-data-dir`, `--load-extension`, `--no-sandbox`, `--disable-web-security`, other). The raw value is **never** stored or logged.
4. Calls `SetEnvironmentVariableW(name, nullptr)` to remove the variable from this process's environment block.
5. Verifies removal with a second read.

*Layer 2 — per-app policy registry override:*

6. Resolves the current process's exe leaf via `GetModuleFileNameW` (e.g. `ms-teams.exe`).
7. For each of `HKCU` and `HKLM`, opens `Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments` and reads the values named `<exe-leaf>` and `*` (covering both per-app and wildcard policy entries).
8. For each detected value, computes the same fingerprint bitmask and records `<hive>:<value-name>` plus the bitmask. **Both hives are logged** so HKLM (admin/GPO-set) values still surface in your forensic signal even though we don't write to HKLM.
9. **HKCU only:** if the fingerprint contains any of `kRemoteDebugging`, `kLoadExtension`, `kNoSandbox`, or `kDisableWebSec`, the value is `RegDeleteValueW`'d. `kUserDataDir` is intentionally excluded from the delete-gate — legitimate kiosk/dev configs set it, and false-positive deletes break those flows.

**macOS** (`webview2_env_sanitizer_mac.mm`):

1. Same env-var flow with `getenv` / `unsetenv`.
2. Scope is currently `"unknown"` — distinguishing `launchctl setenv` vs `~/.zshrc` vs plist origin is doable but requires extra plumbing; the value fingerprint is usually enough.
3. No registry layer — Windows-specific.

The whole thing is wrapped in `try { … } catch (...) {}` and marked `noexcept`. If anything goes wrong, the app launches anyway with whatever clearing succeeded.

---

## Telemetry

The sample is intentionally telemetry-agnostic: it returns `SanitizeResult` and lets you feed it into whatever pipeline you use (App Insights, Sentry, OneDS, ETW, syslog).

- ✅ **Do** emit: var names, scope tags, fingerprint bitmasks, success/failure counts, *plus* the policy hive (`HKCU`/`HKLM`), value name (`<exe>`/`*`), and `policy_keys_cleared` / `policy_keys_failed` counts.
- ❌ **Do not** emit: the raw env var value or the raw registry value content. They can contain user paths, tokens, GUIDs, attacker-supplied content. The fingerprint exists precisely so you don't have to.

A starting Kusto query for the env-var channel — assumes you log one row per detected var, or `mv-expand` first if you log them as parallel arrays:

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

And the parallel query for the registry channel — note that an `HKCU` hit with attack tokens is a **stronger** signal than the env-var equivalent, because the registry channel has no benign scope analog (no equivalent of `process_only`):

```kusto
ClientEvents
| where EventName == "webview2_env_sanitization"
| mv-expand hive  = detected_policy_hives  to typeof(string),
            vname = detected_policy_value_names to typeof(string),
            fp    = detected_policy_fingerprints to typeof(long)
| where binary_and(fp, 1) != 0    // kRemoteDebugging bit
| extend severity = iff(hive == "HKCU", "high (user-writable)", "medium (admin/GPO)")
| summarize attack_attempts = dcount(UserId), devices = dcount(DeviceId)
        by hive, vname, severity, bin(Timestamp, 1d)
```

That gives you the rate of likely-real attack attempts on each channel separately, plus background noise from devs with `--user-data-dir` set somewhere.

## Rollout

If you ship to a large fleet, **gate the entire `SanitizeWebView2EnvironmentVariables()` call on a single feature flag for the first ring or two** — same flag for both layers. A non-zero number of internal devs and IT-managed populations rely on `WEBVIEW2_USER_DATA_FOLDER` (or its registry analog) for legitimate reasons (custom profile paths, kiosk configs, automation). The telemetry is exactly what you need to size that population *before* you flip the default to "block."

Don't split the gate per layer. If only the env-var sanitization is enabled, an attacker who finds that path closed will simply use the registry path — and the WebView2 runtime will read it. One flag, both layers.

In prewarm/helper processes, **don't gate** — feature flags typically aren't loaded that early, and the security tradeoff (force-clear vs. occasional dev-tool breakage in a helper) lands on force-clear.

---

## Validating the fix

Reproduce *both* attacks and confirm CDP doesn't come up.

**Windows — env-var channel:**

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

**Windows — registry channel (the one env-var sanitization alone would miss):**

```powershell
# 1. Make sure the env var is NOT set (force the runtime to fall through to registry)
[Environment]::SetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', $null, 'User')

# 2. Plant the policy registry override under HKCU (no admin needed)
$key = 'HKCU:\Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'yourapp.exe' `
    -Value '--remote-debugging-port=9222 --remote-allow-origins=*' `
    -PropertyType String -Force | Out-Null

# 3. Launch your app
Start-Process "yourapp:"

# 4. Confirm nothing is listening on 9222
Get-NetTCPConnection -State Listen -LocalPort 9222   # should return nothing
Invoke-RestMethod http://127.0.0.1:9222/json         # should fail to connect

# 5. Confirm the value was actively deleted by the sanitizer
Get-ItemProperty -Path $key -Name 'yourapp.exe' -ErrorAction SilentlyContinue
# Should produce no output (value gone). The key itself is left in place — only
# the offending value is deleted.
```

A useful negative test: re-run step 2 with `--user-data-dir=C:\some\path` instead of the CDP flag and confirm the value is **not** deleted (only logged). That validates the `kPolicyDeleteTokens` mask isn't over-reaching.

**macOS:**

```bash
launchctl setenv WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS '--remote-debugging-port=9222 --remote-allow-origins=*'
open -a "YourApp"
lsof -iTCP:9222 -sTCP:LISTEN   # should be empty
```

---

## What this does NOT cover

- **Other policy registry overrides.** The sample inspects and (selectively) cleans `…\AdditionalBrowserArguments\<AppId>` because that's the channel the public PoC abused. The parallel keys for `BrowserExecutableFolder`, `UserDataFolder`, `ChannelSearchKind`, and `ReleaseChannels` are detected via env vars only — extending the registry pass to those is a one-line addition (different `kPolicySubkey` per override) and is the natural next step if your threat model warrants it.
- **AUMID-keyed policy values.** The runtime checks `<AUMID>` before `<exe-leaf>` and `*`. Reading the AUMID requires `IPropertyStore` / `SHGetPropertyStoreForWindow` plumbing that isn't appropriate for a single-file drop-in. If your app has a stable AUMID, pass it explicitly as a third value name in `InspectPolicyHive`.
- **Compromised parent processes.** A malicious parent process can do far worse than set env vars. This is one layer.
- **Other Chromium-embedding runtimes.** CEF, Electron, .NET MAUI's Chromium-backed `BlazorWebView`, etc. have their own env-var stories. This code is WebView2-specific.

---

## Defense in depth — what's tracked, what's punted

A frank inventory so the gap doesn't get implicitly closed by the next reader assuming "registry coverage" means "all of it":

| Channel | Coverage | Status |
|---|---|---|
| `WEBVIEW2_*` env vars | Detected, fingerprinted, scope-tagged, cleared | ✅ Covered |
| `…\AdditionalBrowserArguments\<exe>` (HKCU) | Detected, logged, deleted on attack-token match | ✅ Covered |
| `…\AdditionalBrowserArguments\*` (HKCU)  | Detected, logged, deleted on attack-token match | ✅ Covered |
| `…\AdditionalBrowserArguments\<exe>` and `\*` (HKLM) | Detected, logged | ⚠️ Read-only by design (admin-only path; out of user-level threat model) |
| `…\AdditionalBrowserArguments\<AUMID>` (either hive) | **Not checked** | ❌ Pass an explicit AUMID to `InspectPolicyHive` if your app sets one |
| `…\BrowserExecutableFolder\…` (either hive) | **Not checked at registry layer** | ❌ Env-var equivalent is cleared; registry analog is a one-line addition |
| `…\UserDataFolder\…` (either hive) | **Not checked at registry layer** | ❌ Same as above |
| `…\ChannelSearchKind\…`, `…\ReleaseChannels\…` | **Not checked at registry layer** | ❌ Same as above (downgrade vector — lower priority) |

If you adopt this code, **track those last three rows as a known follow-up** rather than letting them drift into the "we did the registry work" assumption. The pattern in `webview2_env_sanitizer_win.cpp` is reusable: lift `kPolicySubkey` and `kPolicyDeleteTokens` to per-override constants, loop over `{ "AdditionalBrowserArguments", "BrowserExecutableFolder", "UserDataFolder", … }`, and call `InspectPolicyHive` once per subkey. The fingerprint mask should differ per subkey (a non-empty `BrowserExecutableFolder` is *always* worth flagging; there's no benign equivalent of `--user-data-dir`).

## Cost

Roughly 10 µs at startup for the env-var pass plus a few hundred µs for two `RegOpenKeyEx` + `RegQueryValueEx` calls when the policy subkey doesn't exist (the common case). Zero runtime overhead afterwards. There is no good reason for a production WebView2 app *not* to do this.

## References

- [WebView2 Win32 IDL reference — `additionalBrowserArguments` and the `WEBVIEW2_*` env vars](https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl)
- [WebView2 security best practices](https://learn.microsoft.com/microsoft-edge/webview2/concepts/security)
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)

**Code:** [`src/`](./src) — `webview2_env_sanitizer.{hpp,cpp}` + `_win.cpp` + `_mac.mm` + `CMakeLists.txt`. MIT-0.
