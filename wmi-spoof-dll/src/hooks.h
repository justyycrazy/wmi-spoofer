// ============================================================================
//  hooks.h —— MinHook 安装线程入口（hooks.cpp 实现，DllMain 创建线程调用）
// ============================================================================
#pragma once

#include <windows.h>

DWORD WINAPI InstallThread(LPVOID param);
