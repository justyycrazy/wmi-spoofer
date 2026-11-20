// ============================================================================
//  common.h —— 共享类型与全局状态声明（各翻译单元经此共享，定义在对应 .cpp）
// ============================================================================
#pragma once

#include <windows.h>

#include <map>
#include <string>
#include <vector>

// 某个 WMI 类下的属性覆写规则（name 保留配置里的原始大小写，便于日志与 Get/Put）
struct PropRule {
    std::wstring name;
    std::wstring value;
};

// 某个类的完整规则：display 为节名原样（用于日志），props 为属性规则列表
struct ClassRule {
    std::wstring display;
    std::vector<PropRule> props;
    bool denyAll = false; // 节内含 EMPTY=1：该类查询直接返回 0 实例（无值模式）
};

// key = 小写类名（WMI 类名大小写不敏感）；定义于 config.cpp，LoadConfig 后只读
extern std::map<std::wstring, ClassRule> g_rules;
extern bool g_injectChildren; // WMI_SPOOFER_CHILDREN；定义于 config.cpp
extern bool g_logEnabled;     // WMI_SPOOFER_LOG；定义于 config.cpp
extern bool g_logFakePlain;   // WMI_SPOOFER_LOG_FAKE；定义于 config.cpp（Put
                              // 日志假值默认脱敏，此开关 opt-in 明文，仅核对送达时用）

extern wchar_t g_dllPath[MAX_PATH]; // 本 DLL 完整路径（log.cpp 定义，供子进程注入使用）
extern wchar_t g_logPath[MAX_PATH]; // 同目录 wmi-spoofer.log（log.cpp 定义）
