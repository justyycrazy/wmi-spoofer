// ============================================================================
//  parse.cpp —— WQL / 对象路径解析与 VARIANT 辅助实现（无共享全局，纯逻辑）
// ============================================================================
#include "parse.h"

#include "config.h" // ToLower

#include <objbase.h>
#include <oleauto.h>
#include <algorithm>
#include <regex>

std::wstring ParseQueryClass(const wchar_t* wql)
{
    if (!wql || !*wql)
        return L"";
    // std::regex 自身不支持内联 (?i)，用 icase 标志实现大小写不敏感
    static const std::wregex re(L"\\bfrom\\s+([A-Za-z0-9_]+)", std::regex::icase);
    std::wsmatch m;
    std::wstring q(wql);
    if (std::regex_search(q, m, re) && m.size() >= 2)
        return ToLower(m[1].str());
    return L"";
}

// 从对象路径解析类名（小写）与实例判定。形态：[命名空间:]类名[.键=值...]，例：
//   "Win32_BaseBoard"                     -> 类定义（放行真实数据）
//   "Win32_BaseBoard=@"                   -> 单例实例
//   "Win32_Processor.DeviceID=\"CPU0\""   -> 键值实例
//   "root\\cimv2:Win32_BaseBoard=@"       -> 带命名空间（取最后一个冒号后的段）
// 返回小写类名，解析失败返回空串；isInstance 指出路径是否含 '='（即实例对象）。
// 已知限制：键值中含冒号（如 DeviceID="C:"）会把类名切在冒号后——后果安全（解析出
// 的类名不命中规则表 -> 放行真实数据）；三类指纹类的键值（@、"CPU0" 等）均无冒号。
std::wstring ParseObjectPathClass(const wchar_t* path, bool* isInstance)
{
    *isInstance = false;
    if (!path || !*path)
        return L"";
    std::wstring seg(path);
    size_t colon = seg.find_last_of(L':');
    if (colon != std::wstring::npos)
        seg = seg.substr(colon + 1);
    if (seg.empty())
        return L"";
    // 类名在第一个 '.'（键值形态）或 '='（@/键值形态）之前——取两者中更早者。
    // 只按 '.' 截断会让 "Win32_BaseBoard=@" 的类名带上 "=@"、"win32_baseboard=@"
    // 查不到规则表，@ 单例路径（GetObject）伪装静默失效。
    size_t dot = seg.find(L'.');
    size_t eq  = seg.find(L'=');
    size_t cut = std::string::npos;
    if (dot != std::string::npos)
        cut = dot;
    if (eq != std::string::npos && (cut == std::string::npos || eq < cut))
        cut = eq;
    std::wstring cls = (cut == std::string::npos) ? seg : seg.substr(0, cut);
    *isInstance = (eq != std::string::npos);
    return ToLower(cls);
}

// 把任意 VARIANT 转成可读字符串（仅用于日志展示原值）
std::wstring VariantToString(const VARIANT& v)
{
    switch (v.vt) {
    case VT_EMPTY: return L"<EMPTY>";
    case VT_NULL:  return L"<NULL>";
    case VT_BSTR:  return (v.bstrVal ? v.bstrVal : L"<空BSTR>");
    default: {
        VARIANT tmp;
        VariantInit(&tmp);
        if (SUCCEEDED(VariantChangeType(&tmp, const_cast<VARIANT*>(&v), 0, VT_BSTR)) && tmp.bstrVal) {
            std::wstring s = tmp.bstrVal;
            VariantClear(&tmp);
            return s;
        }
        return L"<vt=" + std::to_wstring(v.vt) + L">";
    }
    }
}
