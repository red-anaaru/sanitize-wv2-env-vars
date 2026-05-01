// webview2_env_sanitizer.hpp
//
// Cross-platform helper that neutralizes WebView2-related environment variables
// at process startup, before any WebView2 (Win32) / MSWebView2 (macOS) instance
// is created.
//
// Why: The WebView2 runtime *appends* the contents of WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
// (and honors several other WEBVIEW2_* env vars) to the arguments your app passes to
// CreateCoreWebView2EnvironmentWithOptions. A local, non-admin attacker can therefore
// turn on the Chrome DevTools Protocol (e.g. `--remote-debugging-port=9222`) on *your*
// WebView2 instance and proceed to read cookies (incl. httpOnly), execute arbitrary JS
// in your app's origin, and steal session tokens.
//
// Microsoft's own guidance:
//   "Applications should ensure that the WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
//    environment variable cannot be set by untrusted sources."
//   -- https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl
//
// This single-header + two-source-file drop-in does exactly that. Call
// SanitizeWebView2EnvironmentVariables() as the FIRST line of your wWinMain / main /
// applicationDidFinishLaunching, before any WebView2 type is touched.
//
// Dependencies: C++17, STL only. No WIL, no Boost, no platform SDK beyond <Windows.h>
// on Windows and <cstdlib>/<unistd.h> on macOS/Linux.
//
// License: MIT-0 / public domain. Copy freely.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webview2_security {

// Bitmask describing which suspicious tokens appeared in a cleared env var's value.
// Use this when reporting telemetry: emit the bitmask, NEVER the raw value
// (the value can contain user paths, tokens, or attacker-supplied content).
namespace fingerprint {
inline constexpr uint32_t kRemoteDebugging  = 1u << 0;  // --remote-debugging-port / --remote-debugging-pipe (likely attack)
inline constexpr uint32_t kUserDataDir      = 1u << 1;  // --user-data-dir (often a legitimate dev tool)
inline constexpr uint32_t kLoadExtension    = 1u << 2;  // --load-extension (suspicious)
inline constexpr uint32_t kNoSandbox        = 1u << 3;  // --no-sandbox (suspicious)
inline constexpr uint32_t kDisableWebSec    = 1u << 4;  // --disable-web-security (suspicious)
inline constexpr uint32_t kOtherUnknown     = 1u << 5;  // non-empty but matched none of the above
}  // namespace fingerprint

struct SanitizeResult {
    // Names of WEBVIEW2_* env vars that were found set (and cleared).
    std::vector<std::string> detected_vars;

    // Per-detected-var origin scope, 1:1 with detected_vars:
    //   Windows: "user" (HKCU\Environment), "machine" (HKLM\...\Session Manager\Environment),
    //            or "process_only" (inherited from the parent process — likely a launcher).
    //   macOS / others: currently always "unknown".
    std::vector<std::string> detected_scopes;

    // Per-detected-var fingerprint bitmask of suspicious tokens (see fingerprint:: above).
    // 1:1 with detected_vars. The raw value is never stored.
    std::vector<uint32_t> detected_fingerprints;

    // Names of env vars that were detected but for which the clear call failed.
    std::vector<std::string> failed_vars;

    bool any_detected() const noexcept { return !detected_vars.empty(); }
};

// Returns a bitmask describing which suspicious tokens appear in `value`.
// Pure function, no side effects, safe to call from anywhere.
[[nodiscard]] uint32_t BuildValueFingerprint(std::string_view value) noexcept;

// Clears every WEBVIEW2_* environment variable that the WebView2 runtime honors,
// returning a record of what was found.
//
// MUST be called before any of the following:
//   - CreateCoreWebView2Environment / CreateCoreWebView2EnvironmentWithOptions (Win32)
//   - new CoreWebView2CreationProperties() and friends (WinUI/UWP)
//   - [MSWebView2Environment createWithOptions:...] (macOS preview)
//
// Marked noexcept: this runs extremely early in process startup. An uncaught exception
// here would prevent your app from launching, which is strictly worse than skipping
// sanitization for one process. Internally swallows and best-effort-logs all errors.
//
// [[nodiscard]] because callers should normally forward the result to telemetry —
// silently dropping it would lose your only forensic signal that someone tried.
[[nodiscard]] SanitizeResult SanitizeWebView2EnvironmentVariables() noexcept;

}  // namespace webview2_security
