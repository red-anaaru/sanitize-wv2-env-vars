// webview2_env_sanitizer_mac.mm
// macOS implementation. The MSWebView2 preview SDK on macOS embeds the same
// Chromium engine as Win32 WebView2 and honors the same WEBVIEW2_* env vars.
//
// macOS App Sandbox does NOT strip WEBVIEW2_* env vars — only DYLD_* are stripped —
// so a malicious shell rc / launchctl setenv can still inject into a sandboxed app.

#include "webview2_env_sanitizer.hpp"

#include <array>
#include <cstdlib>   // getenv, unsetenv
#include <exception>
#include <string>

namespace webview2_security {

namespace {

// Subset that the macOS MSWebView2 preview SDK actually honors. The script-debugger
// and channel-selection vars are Windows-specific (script debugger uses a Windows
// named pipe; the channel concept applies to the WebView2 Runtime distribution on
// Windows), so clearing them on macOS would just be busywork.
constexpr std::array<const char*, 3> kDangerousEnvVars = {
    "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
    "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
    "WEBVIEW2_USER_DATA_FOLDER",
};

}  // namespace

SanitizeResult SanitizeWebView2EnvironmentVariables() noexcept {
    SanitizeResult result;
    try {
        for (const char* name : kDangerousEnvVars) {
            const char* value = std::getenv(name);
            if (value == nullptr) continue;

            result.detected_vars.emplace_back(name);
            // TODO: on macOS we don't yet distinguish launchctl / plist / shell-rc origins.
            // Treat all as "unknown" so the telemetry shape matches Windows.
            result.detected_scopes.emplace_back("unknown");
            result.detected_fingerprints.push_back(BuildValueFingerprint(value));

            if (::unsetenv(name) != 0) {
                result.failed_vars.emplace_back(name);
            }
        }
    } catch (const std::exception&) {
        // Swallow — see header comment. Never block process startup.
    } catch (...) {
        // Swallow.
    }
    return result;
}

}  // namespace webview2_security
