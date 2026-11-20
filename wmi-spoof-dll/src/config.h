// ============================================================================
//  config.h —— 注入参数解析（环境变量 WMI_SPOOFER_* -> 规则表）
// ============================================================================
#pragma once

#include <string>

void LoadConfig(); // 读取注入环境变量，构建 g_rules（InstallThread 在装 hook 前调用）

std::wstring TrimW(const std::wstring& s);
std::wstring ToLower(std::wstring s);

// 读取环境变量并去两端空白；变量不存在或为空返回 false（= 该项走真实值）
bool GetEnvValue(const wchar_t* name, std::wstring& out);

// 开关型环境变量：缺失用默认值；"0"/false 视为关，其余视为开
bool EnvFlag(const wchar_t* name, bool def);

// 故障注入开关（仅测试用）：WMI_SPOOFER_FAULT=token1,token2 逗号分隔，大小写不敏感。
// token 清单：
//   createhook —— InstallThread 模拟首个必需 hook 的 MH_CreateHook 失败
//   enable     —— InstallThread 模拟 MH_ENABLE 批量启用失败
//   resume     —— launcher（Rust 侧自行读取）/ 子进程传播路径模拟 ResumeThread 失败
//   csinit     —— CReplayEnum 构造模拟临界区创建失败（回归构造失败清理路径）
// 未设置时恒为 false；仅安装与传播路径调用，热路径无影响。
bool FaultEnabled(const wchar_t* token);

// WMI_SPOOFER_EMPTY 的 token -> 对应 WMI 类名（大小写不敏感，支持简称）；未知返回 null
const wchar_t* EmptyTokenToClass(const std::wstring& token);
