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
    auto sanitize = webview2_security::SanitizeWebView2EnvironmentVariables();

    // ... your normal startup: COM init, logging, ECS/config, etc. ...

    if (sanitize.any_detected()) {
        // Once your logging / telemetry pipeline is initialized, report the result.
        // Emit ONLY: var names, scopes, fingerprint bitmasks. NEVER raw values.
        // ReportTelemetry("webview2_env_sanitization", sanitize);
    }

    // ... CreateCoreWebView2EnvironmentWithOptions(...) etc. ...
    return 0;
}

#elif defined(__APPLE__)

// Objective-C++ — rename the file to .mm for the real app.
// In your AppDelegate's applicationDidFinishLaunching: (or in main() before NSApplicationMain
// for a fully belt-and-braces approach), call:
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
