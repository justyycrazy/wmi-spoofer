// ============================================================================
//  config.cpp —— 注入参数解析实现（g_rules / g_injectChildren / g_logEnabled 定义处）
// ============================================================================
#include "config.h"

#include "common.h"
#include "log.h"

#include <algorithm>
#include <map>
#include <utility>

// key = 小写类名（WMI 类名大小写不敏感）；LoadConfig 之后只读，hook 层无锁查询
std::map<std::wstring, ClassRule> g_rules;
bool g_injectChildren = true; // WMI_SPOOFER_CHILDREN
bool g_logEnabled     = true; // WMI_SPOOFER_LOG
bool g_logFakePlain   = false; // WMI_SPOOFER_LOG_FAKE（默认脱敏）

std::wstring TrimW(const std::wstring& s)
{
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos)
        return L"";
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::wstring ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

// 读取环境变量并去两端空白；变量不存在或为空返回 false（= 该项走真实值）
bool GetEnvValue(const wchar_t* name, std::wstring& out)
{
    DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0)
        return false;
    std::vector<wchar_t> buf(n, L'\0');
    GetEnvironmentVariableW(name, buf.data(), n);
    out = TrimW(buf.data());
    return !out.empty();
}

// 开关型环境变量：缺失用默认值；"0"/false 视为关，其余视为开
bool EnvFlag(const wchar_t* name, bool def)
{
    std::wstring v;
    if (!GetEnvValue(name, v))
        return def;
    return !(v == L"0" || _wcsicmp(v.c_str(), L"false") == 0);
}

// 故障注入开关（测试用，见 config.h token 清单）。仅安装/传播路径调用，
// 每次直读环境变量即可：缺省（未设置）零开销，且便于单测直接验证。
bool FaultEnabled(const wchar_t* token)
{
    std::wstring list;
    if (!GetEnvValue(L"WMI_SPOOFER_FAULT", list))
        return false;
    const std::wstring want = ToLower(token);
    size_t start = 0;
    while (true) {
        size_t comma = list.find(L',', start);
        std::wstring t = ToLower(TrimW(list.substr(
            start, (comma == std::wstring::npos) ? std::wstring::npos : comma - start)));
        if (t == want)
            return true;
        if (comma == std::wstring::npos)
            return false;
        start = comma + 1;
    }
}

// 内置三类指纹类：环境变量名 -> WMI 类名 + 覆写属性
struct EnvClassSpec {
    const wchar_t* env;
    const wchar_t* cls;
    const wchar_t* prop;
};
static const EnvClassSpec kEnvClasses[] = {
    { L"WMI_SPOOFER_BOARD", L"Win32_BaseBoard",  L"SerialNumber" },
    { L"WMI_SPOOFER_CPU",   L"Win32_Processor",  L"ProcessorId"  },
    { L"WMI_SPOOFER_DISK",  L"Win32_DiskDrive",  L"SerialNumber" },
};

// WMI_SPOOFER_EMPTY 的 token -> 对应 WMI 类名（大小写不敏感，支持简称）；未知返回 null。
// 调用方须判空（未知 token 时本函数返回 null，如 LoadConfig 会记日志后忽略）。
const wchar_t* EmptyTokenToClass(const std::wstring& token)
{
    const std::wstring low = ToLower(token);
    if (low == L"board" || low == L"baseboard")
        return L"Win32_BaseBoard";
    if (low == L"cpu" || low == L"processor")
        return L"Win32_Processor";
    if (low == L"disk" || low == L"diskdrive")
        return L"Win32_DiskDrive";
    return nullptr;
}

// 读取注入环境变量，构建规则表。无任何变量时保持 g_rules 为空——
// 一切查询放行真实数据（安全兜底）。
void LoadConfig()
{
    g_injectChildren = EnvFlag(L"WMI_SPOOFER_CHILDREN", true);
    g_logEnabled     = EnvFlag(L"WMI_SPOOFER_LOG", true);
    g_logFakePlain   = EnvFlag(L"WMI_SPOOFER_LOG_FAKE", false);

    g_rules.clear();

    // 无值模式：WMI_SPOOFER_EMPTY=board,cpu,disk（逗号分隔，大小写不敏感）
    std::wstring emptyList;
    std::map<std::wstring, bool> denyCls; // 小写类名 -> 该类 EMPTY
    if (GetEnvValue(L"WMI_SPOOFER_EMPTY", emptyList)) {
        size_t start = 0;
        while (true) {
            size_t comma = emptyList.find(L',', start);
            std::wstring token = TrimW(emptyList.substr(
                start, (comma == std::wstring::npos) ? std::wstring::npos : comma - start));
            if (!token.empty()) {
                if (const wchar_t* cls = EmptyTokenToClass(ToLower(token)))
                    denyCls[ToLower(cls)] = true;
                else
                    Log(L"[!] WMI_SPOOFER_EMPTY 含未知 token：%s", token.c_str());
            }
            if (comma == std::wstring::npos)
                break;
            start = comma + 1;
        }
    }

    for (const EnvClassSpec& spec : kEnvClasses) {
        ClassRule rule;
        rule.display = spec.cls;

        if (denyCls[ToLower(spec.cls)]) {
            rule.denyAll = true; // 无值模式：该类查询直接返回 0 实例
        } else {
            std::wstring val;
            if (GetEnvValue(spec.env, val))
                rule.props.push_back({ spec.prop, val });
        }

        if (rule.denyAll || !rule.props.empty())
            g_rules[ToLower(spec.cls)] = std::move(rule);
    }

    Log(L"配置加载完成：%u 个类规则（CHILDREN=%d，LOG=%d，LOG_FAKE=%d）",
        static_cast<unsigned>(g_rules.size()),
        g_injectChildren ? 1 : 0, g_logEnabled ? 1 : 0, g_logFakePlain ? 1 : 0);

    // 逐条记录生效配置：保留"本次下发了什么"的现场，供与 Put 记录对照
    for (const auto& kv : g_rules) {
        const ClassRule& rule = kv.second;
        if (rule.denyAll) {
            Log(L"  %s：EMPTY（查询返回 0 实例）", rule.display.c_str());
            continue;
        }
        for (const PropRule& p : rule.props)
            Log(L"  %s：%s=%s", rule.display.c_str(), p.name.c_str(), MaskValue(p.value).c_str());
    }
}
