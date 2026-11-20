// ============================================================================
//  inject.cpp —— 子进程注入与 hook 就绪握手实现
// ============================================================================
#include "inject.h"

#include "common.h"
#include "log.h"

#include <cwchar>

// ----------------------------------------------------------------------------
// 子进程注入（VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)）
// ----------------------------------------------------------------------------

bool InjectSelf(HANDLE hProcess, DWORD pid)
{
    if (!g_dllPath[0])
        return false; // BuildPaths 降级：自身路径未知，无法注入

    size_t chars = wcslen(g_dllPath) + 1;
    SIZE_T bytes = chars * sizeof(wchar_t);

    LPVOID remote = VirtualAllocEx(hProcess, nullptr, bytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        Log(L"[!] 子进程注入失败（PID=%lu）：VirtualAllocEx 错误 %lu",
            pid, GetLastError());
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote, g_dllPath, bytes, &written)) {
        Log(L"[!] 子进程注入失败（PID=%lu）：WriteProcessMemory 错误 %lu",
            pid, GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoad = k32 ? GetProcAddress(k32, "LoadLibraryW") : nullptr;
    if (!pLoad) {
        Log(L"[!] 子进程注入失败：找不到 kernel32!LoadLibraryW");
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE th = CreateRemoteThread(hProcess, nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoad),
                                   remote, 0, nullptr);
    if (!th) {
        Log(L"[!] 子进程注入失败（PID=%lu）：CreateRemoteThread 错误 %lu",
            pid, GetLastError());
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        return false;
    }

    // 等待 LoadLibraryW 真正完成。超时/失败不得判成功，也不得释放 remote：
    // 远程线程可能仍在读取该缓冲（释放构成跨进程 UAF），内存随子进程终止由系统回收
    DWORD w = WaitForSingleObject(th, 5000);
    if (w != WAIT_OBJECT_0) {
        Log(L"[!] 子进程注入（PID=%lu）：等待 LoadLibraryW 超时或失败（w=%lu）", pid, w);
        CloseHandle(th);
        return false;
    }
    DWORD exitCode = 0;
    GetExitCodeThread(th, &exitCode);
    CloseHandle(th);
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE); // 线程已结束，路径缓冲可安全释放

    if (exitCode == 0) {
        Log(L"[!] 子进程注入失败（PID=%lu）：LoadLibraryW 返回 0（检查 DLL 与子进程位数是否一致）", pid);
        return false;
    }
    Log(L"子进程注入成功：PID=%lu 已加载 wmi-spoofer.dll", pid);
    return true;
}

// ----------------------------------------------------------------------------
// hook 就绪握手：DLL 全部 hook 启用后置位 Local\wmi-spoofer-ready-<pid> 事件。
// 注入方（launcher / 父进程的 CreateProcess hook）等待该事件替代固定 Sleep，
// 确定性保证"放行子进程/恢复主线程时 hook 已装好"，消除慢机下的静默失效。
// 事件名双方由 PID 独立推导，无环境变量协议变更。
// ----------------------------------------------------------------------------

static void HookReadyEventName(DWORD pid, wchar_t (&name)[64])
{
    swprintf(name, 64, L"Local\\wmi-spoofer-ready-%lu", pid);
}

// 就绪事件句柄。命名内核对象在最后一个句柄关闭时即被销毁——
// "信号保留"只对仍存活的对象成立，因此 DLL 必须持有句柄到进程退出，
// 否则注入方永远打不开该事件。
static HANDLE g_readyEvent = nullptr;

void SignalHookReady()
{
    wchar_t name[64];
    HookReadyEventName(GetCurrentProcessId(), name);
    g_readyEvent = CreateEventW(nullptr, TRUE /*manual-reset*/, FALSE, name);
    if (!g_readyEvent) {
        Log(L"[!] 创建 hook 就绪事件失败：%lu", GetLastError());
        return;
    }
    SetEvent(g_readyEvent);
    // 刻意不 CloseHandle：对象需存活到进程退出供注入方等待
}

bool WaitForHookReady(DWORD pid, DWORD timeoutMs)
{
    wchar_t name[64];
    HookReadyEventName(pid, name);
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        HANDLE ev = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (ev) {
            ULONGLONG now = GetTickCount64();
            DWORD remain = (now < deadline) ? static_cast<DWORD>(deadline - now) : 0;
            const bool signaled = WaitForSingleObject(ev, remain) == WAIT_OBJECT_0;
            CloseHandle(ev);
            return signaled;
        }
        if (GetTickCount64() >= deadline)
            return false;
        Sleep(50);
    }
}
