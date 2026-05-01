// webview2_env_sanitizer.cpp
// Platform-agnostic pieces of the WebView2 env-var sanitizer.

#include "webview2_env_sanitizer.hpp"

namespace webview2_security {

uint32_t BuildValueFingerprint(std::string_view value) noexcept {
    using namespace fingerprint;
    uint32_t fp = 0;
    auto contains = [&](std::string_view needle) {
        return value.find(needle) != std::string_view::npos;
    };
    if (contains("--remote-debugging"))     fp |= kRemoteDebugging;
    if (contains("--user-data-dir"))        fp |= kUserDataDir;
    if (contains("--load-extension"))       fp |= kLoadExtension;
    if (contains("--no-sandbox"))           fp |= kNoSandbox;
    if (contains("--disable-web-security")) fp |= kDisableWebSec;
    if (fp == 0 && !value.empty())          fp |= kOtherUnknown;
    return fp;
}

}  // namespace webview2_security
