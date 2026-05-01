// main_example.cpp
// Minimal illustration of where to place the sanitizer call in a typical
// WebView2-hosting app. Compile only one of the entry points for your platform.

#include "webview2_env_sanitizer.hpp"

#if defined(_WIN32)

#include <Windows.h>

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    // FIRST line of real work. Before any WebView2 type is referenced, before
    // CoInitialize, before logging — anything that might transitively load the
    // WebView2 loader DLL.
    //
    // This single call performs BOTH:
    //   - clears the seven WEBVIEW2_* env vars in this process's PEB, and
    //   - inspects (and selectively deletes) per-app overrides under
    //     {HKCU,HKLM}\Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments.
    // Gate it behind one feature flag if you're staging a rollout — never split
    // the gate per layer (the attacker would simply pivot to the open one).
    auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();

    // ... your normal startup: COM init, logging, ECS/config, etc. ...

    if (sanitize.any_detected()) {
        // Once your logging / telemetry pipeline is initialized, report the result.
        // Emit ONLY: var names, scopes, fingerprint bitmasks, policy hives + value
        // names + cleared/failed counts. NEVER raw env or registry values.
        // ReportTelemetry("webview2_env_sanitization", sanitize);
    }

    // ... CreateCoreWebView2EnvironmentWithOptions(...) etc. ...
    return 0;
}

#elif defined(__APPLE__)

// Objective-C++ — rename the file to .mm for the real app.
// In your AppDelegate's applicationDidFinishLaunching: (or in main() before
// NSApplicationMain, for the earliest possible call site), call:
//
//   auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();
//
// before any [MSWebView2Environment ...] call.
//
// If your app has a "prewarm" helper process that creates the WebView2 environment
// outside of AppDelegate, call the sanitizer at the top of that helper's main() too.

int main(int, char**) {
    auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();
    // ... NSApplicationMain(...) ...
    (void)sanitize;
    return 0;
}

#endif
