// webview2_env_sanitizer_win.cpp
// Windows implementation. Two layers:
//   1. Clears the seven WEBVIEW2_* env vars the runtime honors and reports whether
//      each was set in HKCU, HKLM, or only in the current process block.
//   2. Inspects the per-app policy registry overrides under
//        {HKCU,HKLM}\Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments\<exe|*>
//      that the runtime falls through to when env vars are absent. HKCU values
//      whose fingerprint contains attack tokens are deleted; HKLM is logged
//      only (admin-only path; out of the user-level threat model).

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

// ---------- Policy registry override layer ----------
//
// Per the WebView2 Win32 IDL, when no env-var override is found the runtime
// reads per-app values from this subkey under both HKLM (preferred) and HKCU:
//
//   Software\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments\<AppId>
//
// where <AppId> is the AUMID, then the exe leaf name, then "*". We check the
// exe leaf and "*" — covering the AUMID would require shell32 + per-process
// AUMID lookup, which is overkill for this drop-in.

constexpr const wchar_t* kPolicySubkey =
    L"Software\\Policies\\Microsoft\\Edge\\WebView2\\AdditionalBrowserArguments";

// Tokens that justify actively deleting an HKCU policy value. Strict subset of
// the fingerprint mask: --user-data-dir is intentionally NOT here because
// legitimate kiosk / dev configs set it.
constexpr uint32_t kPolicyDeleteTokens =
    fingerprint::kRemoteDebugging |
    fingerprint::kLoadExtension |
    fingerprint::kNoSandbox |
    fingerprint::kDisableWebSec;

// Returns the exe leaf name (e.g. L"ms-teams.exe") of the current process, or
// empty on failure. Case is preserved as the OS reports it; registry lookups
// are case-insensitive so we don't normalize.
std::wstring GetExeLeafName() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD got = ::GetModuleFileNameW(nullptr, buf.data(),
                                         static_cast<DWORD>(buf.size()));
        if (got == 0) return {};
        if (got < buf.size()) {
            buf.resize(got);
            break;
        }
        // Truncated: grow and retry. Bounded so we don't loop forever on a
        // pathological filesystem.
        if (buf.size() >= 32 * 1024) return {};
        buf.resize(buf.size() * 2);
    }
    auto pos = buf.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? buf : buf.substr(pos + 1);
}

// Reads a REG_SZ / REG_EXPAND_SZ value from kPolicySubkey under `root`.
// Other value types are ignored — WebView2 expects a string and would not
// honor them anyway.
struct PolicyValue { std::wstring value; bool present = false; };
PolicyValue ReadPolicyValue(HKEY root, const wchar_t* value_name) {
    HKEY key{};
    if (::RegOpenKeyExW(root, kPolicySubkey, 0,
                        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return {};
    }
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = ::RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0) {
        ::RegCloseKey(key);
        return {};
    }
    std::wstring buf(bytes / sizeof(wchar_t), L'\0');
    rc = ::RegQueryValueExW(key, value_name, nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(buf.data()), &bytes);
    ::RegCloseKey(key);
    if (rc != ERROR_SUCCESS) return {};
    while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    return {std::move(buf), true};
}

// Deletes a value under HKCU\<kPolicySubkey>. HKCU only — we never modify HKLM.
bool DeleteHkcuPolicyValue(const wchar_t* value_name) {
    HKEY key{};
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kPolicySubkey, 0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return false;
    }
    LONG rc = ::RegDeleteValueW(key, value_name);
    ::RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

void InspectPolicyHive(HKEY root,
                       const char* hive_label,
                       const std::wstring& exe_leaf,
                       SanitizeResult& result) {
    // Per-exe lookup first (more specific), then wildcard.
    std::vector<std::wstring> value_names;
    if (!exe_leaf.empty()) value_names.push_back(exe_leaf);
    value_names.emplace_back(L"*");

    for (const auto& vname : value_names) {
        auto pv = ReadPolicyValue(root, vname.c_str());
        if (!pv.present) continue;

        std::string vname_utf8 = Utf16ToUtf8(vname);
        uint32_t fp = BuildValueFingerprint(Utf16ToUtf8(pv.value));

        result.detected_policy_hives.emplace_back(hive_label);
        result.detected_policy_value_names.push_back(vname_utf8);
        result.detected_policy_fingerprints.push_back(fp);

        // Active mitigation: HKCU only, and only when attack tokens are present.
        // HKLM is read-only to non-admins and would require elevation we don't
        // assume; a legitimate `--user-data-dir`-only HKCU value is left alone
        // (kPolicyDeleteTokens does not include kUserDataDir).
        if (root == HKEY_CURRENT_USER && (fp & kPolicyDeleteTokens) != 0) {
            std::string id = std::string(hive_label) + ":" + vname_utf8;
            if (DeleteHkcuPolicyValue(vname.c_str())) {
                result.policy_keys_cleared.push_back(std::move(id));
            } else {
                result.policy_keys_failed.push_back(std::move(id));
            }
        }
    }
}

}  // namespace

SanitizeResult SanitizeWebView2EnvironmentVariables() noexcept {
    SanitizeResult result;
    try {
        // ----- Layer 1: env vars -----
        for (const wchar_t* name : kDangerousEnvVars) {
            auto current = TryGetEnv(name);
            if (!current.present) continue;

            std::string name_utf8 = Utf16ToUtf8(name);
            result.detected_vars.push_back(name_utf8);
            result.detected_scopes.push_back(DetectScope(name));
            result.detected_fingerprints.push_back(
                BuildValueFingerprint(Utf16ToUtf8(current.value)));

            // Pass nullptr to remove the variable from the current process block.
            // This affects only this process and its descendants — we do not
            // touch the persistent HKCU\Environment / HKLM Environment hives,
            // because those are general-purpose env-var stores that may legitimately
            // hold values unrelated to WebView2.
            ::SetEnvironmentVariableW(name, nullptr);

            // Verify it actually went away (defense against pathological CRT shims).
            auto verify = TryGetEnv(name);
            if (verify.present) {
                result.failed_vars.push_back(std::move(name_utf8));
            }
        }

        // ----- Layer 2: per-app policy registry override -----
        // The WebView2 runtime falls through to these keys when no env-var
        // override is set, so closing only the env-var path leaves a parallel
        // attack channel open. Unlike HKCU\Environment, the policy subkey is
        // WebView2-specific, so deleting attack values there is low-collateral.
        const std::wstring exe_leaf = GetExeLeafName();
        InspectPolicyHive(HKEY_CURRENT_USER,  "HKCU", exe_leaf, result);
        InspectPolicyHive(HKEY_LOCAL_MACHINE, "HKLM", exe_leaf, result);
    } catch (const std::exception&) {
        // Swallow: see header comment. Do not block process startup.
    } catch (...) {
        // Swallow.
    }
    return result;
}

}  // namespace webview2_security
