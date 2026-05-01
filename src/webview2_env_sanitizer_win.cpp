// webview2_env_sanitizer_win.cpp
// Windows implementation: clears the seven WEBVIEW2_* env vars the runtime honors
// and reports whether each was set in HKCU, HKLM, or only in the current process block.

#include "webview2_env_sanitizer.hpp"

#include <Windows.h>

#include <array>
#include <exception>
#include <string>
#include <vector>

namespace webview2_security {

namespace {

// All env vars the WebView2 runtime reads, per the Win32 IDL reference.
// https://learn.microsoft.com/microsoft-edge/webview2/reference/win32/webview2-idl
constexpr std::array<const wchar_t*, 7> kDangerousEnvVars = {
    L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",  // CDP injection, sandbox flags, extensions...
    L"WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",     // Redirect to attacker-controlled WebView2 binary
    L"WEBVIEW2_USER_DATA_FOLDER",              // Redirect profile / cookies
    L"WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",      // Script debugger hook
    L"WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",      // Script debugger hook
    L"WEBVIEW2_CHANNEL_SEARCH_KIND",           // Channel-selection override (downgrade vector)
    L"WEBVIEW2_RELEASE_CHANNELS",              // Channel-selection override (downgrade vector)
};

std::string Utf16ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                    nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                          out.data(), len, nullptr, nullptr);
    return out;
}

// Returns the env var's value, or std::nullopt-equivalent (empty + has_value=false).
struct EnvValue { std::wstring value; bool present = false; };
EnvValue TryGetEnv(const wchar_t* name) {
    DWORD needed = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) {
        return {};  // not present, or empty (treat empty as "not interesting")
    }
    std::wstring buf(needed, L'\0');
    DWORD got = ::GetEnvironmentVariableW(name, buf.data(), needed);
    if (got == 0 || got >= needed) return {};
    buf.resize(got);
    return {std::move(buf), true};
}

bool RegistryValueExists(HKEY root, const wchar_t* subkey, const wchar_t* value_name) {
    HKEY key{};
    if (::RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return false;
    }
    LONG rc = ::RegQueryValueExW(key, value_name, nullptr, nullptr, nullptr, nullptr);
    ::RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

// Distinguish where the env var came from. This matters because:
//   "user"         => persistent attack on this user account (high signal)
//   "machine"      => admin/GPO config, more likely legitimate
//   "process_only" => inherited from a launcher (e.g. an IDE) — possibly legitimate dev work
std::string DetectScope(const wchar_t* name) {
    if (RegistryValueExists(HKEY_CURRENT_USER, L"Environment", name)) {
        return "user";
    }
    if (RegistryValueExists(HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Control\\Session Manager\\Environment",
                            name)) {
        return "machine";
    }
    return "process_only";
}

}  // namespace

SanitizeResult SanitizeWebView2EnvironmentVariables() noexcept {
    SanitizeResult result;
    try {
        for (const wchar_t* name : kDangerousEnvVars) {
            auto current = TryGetEnv(name);
            if (!current.present) continue;

            std::string name_utf8 = Utf16ToUtf8(name);
            result.detected_vars.push_back(name_utf8);
            result.detected_scopes.push_back(DetectScope(name));
            result.detected_fingerprints.push_back(
                BuildValueFingerprint(Utf16ToUtf8(current.value)));

            // Pass nullptr to remove the variable from the current process block.
            // This affects only this process and its descendants — we cannot and
            // do not touch the persistent registry hives.
            ::SetEnvironmentVariableW(name, nullptr);

            // Verify it actually went away (defense against pathological CRT shims).
            auto verify = TryGetEnv(name);
            if (verify.present) {
                result.failed_vars.push_back(std::move(name_utf8));
            }
        }
    } catch (const std::exception&) {
        // Swallow: see header comment. Do not block process startup.
    } catch (...) {
        // Swallow.
    }
    return result;
}

}  // namespace webview2_security
