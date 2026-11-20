// ============================================================================
//  inject.h —— 子进程注入与 hook 就绪握手
// ============================================================================
#pragma once

#include <windows.h>

// 子进程注入（VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)）。
// 失败只记日志不抛出；g_dllPath 未知（BuildPaths 降级）时直接返回。
// 返回 true = LoadLibraryW 已在子进程完成（调用方可据此决定是否等待就绪）。
bool InjectSelf(HANDLE hProcess, DWORD pid);

// 等待目标进程的 hook 就绪事件；超时直接返回（调用方照常放行）。
// 返回 true = 已等到事件置位；false = 超时/打不开（调用方据此记日志）。
bool WaitForHookReady(DWORD pid, DWORD timeoutMs);

// 安装线程在全部 hook 启用成功后调用；任何失败路径都不得调用
void SignalHookReady();
