// ============================================================================
//  log.h —— 日志与路径（Log / MaskValue / BuildPaths / LogInit）
// ============================================================================
#pragma once

#include <windows.h>

#include <string>

void LogInit(); // 初始化日志互斥（DllMain 在 DLL_PROCESS_ATTACH 调用一次）

// 由 DLL 自身路径推导出同目录下的 log 路径（DllMain 在 DLL_PROCESS_ATTACH 调用）
void BuildPaths(HMODULE hSelf);

// 追加一行 UTF-8 日志（printf 风格；g_logEnabled 或 g_logPath 不可用时静默禁用）。
// 异常安全——UTF-8 转换缓冲用 nothrow new（有堆分配，但分配失败
// 不抛出），OOM 静默丢行、绝不抛出；因此允许在 GuardHr 边界之外调用（proxies.h
// 各 COM 方法的入口日志、*Async 纯转发方法等），调用点无需自备异常边界
void Log(const wchar_t* fmt, ...) noexcept;

// 异常处理器专用的降级日志——全程栈缓冲、无 C++ 分配、不抛出，
// 专为 catch 块设计（比 Log 紧凑：只求把要点落盘）。catch 路径一律用本函数。
void LogFallback(const wchar_t* fmt, ...) noexcept;

// 值脱敏：真实硬件指纹只保留首尾各 2 字符与长度（用于日志输出）
std::wstring MaskValue(const std::wstring& v);
