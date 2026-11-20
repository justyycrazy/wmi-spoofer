// ============================================================================
//  hooks.cpp —— MinHook hook 函数与安装线程
//
//  hook 点 1：CoCreateInstance / CoCreateInstanceEx（combase.dll）——捕获
//  CLSID_WbemLocator 请求，把返回的 IWbemLocator 换成 CWbemLocatorProxy；
//  hook 点 2：CreateProcessW/A（kernel32.dll）——仅 WMI_SPOOFER_CHILDREN=1 时
//  向子进程传播注入（兼容 PyInstaller onefile）。
// ============================================================================
#include "hooks.h"

#include <MinHook.h>

#include "common.h"
#include "config.h"
#include "guard.h"
#include "inject.h"
#include "log.h"
#include "proxies.h"

// ----------------------------------------------------------------------------
// 原函数指针与替换函数
// ----------------------------------------------------------------------------

typedef HRESULT(WINAPI* PFN_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT(WINAPI* PFN_CoCreateInstanceEx)(REFCLSID, LPUNKNOWN, DWORD,
                                                COSERVERINFO*, DWORD, MULTI_QI*);
typedef BOOL(WINAPI* PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                         LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                         LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

static PFN_CoCreateInstance   g_realCoCreateInstance   = nullptr;
static PFN_CoCreateInstanceEx g_realCoCreateInstanceEx = nullptr;
static PFN_CreateProcessW     g_realCreateProcessW     = nullptr;
static PFN_CreateProcessA     g_realCreateProcessA     = nullptr;

static HRESULT WINAPI Hooked_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
                                              DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
    HRESULT hr = g_realCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    // 直接请求 Locator 与先请求 IUnknown 再 QI 都是合法客户端用法，一并包装
    // （代理的 QI(IID_IUnknown/IID_IWbemLocator) 均合法）；聚合（pUnkOuter 非空）
    // 不包装，避免破坏 COM 身份。
    if (SUCCEEDED(hr) && ppv && *ppv && pUnkOuter == nullptr &&
        rclsid == CLSID_WbemLocator &&
        (riid == IID_IWbemLocator || riid == IID_IUnknown)) {
        // 包装段在异常边界内：经 QI 取真实 Locator 再包装（不依赖
        // IUnknown* 与 IWbemLocator* 同值）；new 失败/QI 失败时 *ppv 仍指向
        // 真实对象——降级为未包装结果，调用方可见的 hr 不变
        hr = GuardHr([&]() -> HRESULT {
            Log(L"捕获 CLSID_WbemLocator（%s），包装 IWbemLocator",
                (riid == IID_IWbemLocator) ? L"直接请求" : L"经 IUnknown 创建，QI 可达");
            void* wrapped = nullptr;
            if (TryWrapLocatorOutput(static_cast<IUnknown*>(*ppv), &wrapped))
                *ppv = wrapped;
            return hr;
        }, hr);
    }
    return hr;
}

static HRESULT WINAPI Hooked_CoCreateInstanceEx(REFCLSID rclsid, LPUNKNOWN pUnkOuter,
                                                DWORD dwClsContext, COSERVERINFO* pServerInfo,
                                                DWORD dwCount, MULTI_QI* pResults)
{
    HRESULT hr = g_realCoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext,
                                          pServerInfo, dwCount, pResults);
    // 逐项接受 IWbemLocator / IUnknown 两种请求 IID；聚合不包装（语义同上）
    if (SUCCEEDED(hr) && pResults && pUnkOuter == nullptr && rclsid == CLSID_WbemLocator) {
        // MULTI_QI 数组里每个请求的接口单独检查；逐项异常边界，
        // 经 QI 取真实 Locator，语义与 CoCreateInstance 版一致
        for (DWORD i = 0; i < dwCount; ++i) {
            if (pResults[i].hr == S_OK && pResults[i].pItf && pResults[i].pIID &&
                (*pResults[i].pIID == IID_IWbemLocator || *pResults[i].pIID == IID_IUnknown)) {
                pResults[i].hr = GuardHr([&]() -> HRESULT {
                    Log(L"捕获 CLSID_WbemLocator（CoCreateInstanceEx），包装 IWbemLocator");
                    void* wrapped = nullptr;
                    if (TryWrapLocatorOutput(static_cast<IUnknown*>(pResults[i].pItf),
                                             &wrapped))
                        pResults[i].pItf = static_cast<IWbemLocator*>(wrapped);
                    return S_OK;
                }, S_OK);
            }
        }
    }
    return hr;
}

// 子进程路径的 ResumeThread 检查。进程已创建、无法回退，失败只能记录，
// 但绝不能静默——否则主线程挂起的子进程会让调用方永久等待。
// ResumeThread 返回递减前的挂起计数：0 = 本未挂起，1 = 已完全恢复，
// >1 = 递减后仍挂起（嵌套挂起，如目标自己加挂）——继续递减直至 <=1，
// 有界防死循环；(DWORD)-1 = 失败。
static void ResumeChildMainThread(DWORD pid, HANDLE hThread)
{
    // 故障注入（测试用）：模拟 ResumeThread 失败
    const bool faultResume = FaultEnabled(L"resume");
    DWORD resumed = faultResume ? static_cast<DWORD>(-1) : ResumeThread(hThread);
    for (int attempts = 0; resumed != static_cast<DWORD>(-1) && resumed > 1 && attempts < 16;
         ++attempts)
        resumed = faultResume ? static_cast<DWORD>(-1) : ResumeThread(hThread);
    if (resumed == static_cast<DWORD>(-1)) {
        if (faultResume)
            Log(L"[!] [fault] 模拟 ResumeThread 失败（PID=%lu）：子进程主线程仍挂起", pid);
        else
            Log(L"[!] ResumeThread 失败（PID=%lu，错误 %lu）：子进程主线程仍挂起，"
                L"调用方需自行处理",
                pid, GetLastError());
    } else if (resumed > 1) {
        Log(L"[!] ResumeThread 有界重试后挂起计数仍 >1（PID=%lu，计数=%lu）："
            L"子进程主线程可能仍被嵌套挂起",
            pid, resumed);
    }
}

static BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    const BOOL callerWantsSuspend = (dwCreationFlags & CREATE_SUSPENDED) ? TRUE : FALSE;
    // 仅在确定要注入时才追加 CREATE_SUSPENDED：若无条件挂起而后续又不恢复
    // （传播关闭 / lpProcessInformation 为空），子进程主线程将被永久挂起
    const bool inject = g_injectChildren && lpProcessInformation != nullptr;
    BOOL ok = g_realCreateProcessW(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles,
                                   dwCreationFlags | (inject ? CREATE_SUSPENDED : 0),
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                                   lpProcessInformation);
    if (ok && inject) {
        // 传播段在异常边界内：任何异常都不改变 CreateProcess 的返回值，
        // catch 中 best-effort 恢复主线程，避免子进程卡死在挂起态
        try {
            Log(L"CreateProcessW：子进程 PID=%lu，传播注入", lpProcessInformation->dwProcessId);
            // 注入失败时跳过就绪等待（消除无效 3s 阻塞）；注入成功则无论
            // 调用方是否要求挂起都先等就绪——主线程挂起不影响 DLL 安装线程，
            // 有界等待闭合"恢复后早期 WMI 调用未命中"的空窗
            if (InjectSelf(lpProcessInformation->hProcess, lpProcessInformation->dwProcessId)) {
                if (!WaitForHookReady(lpProcessInformation->dwProcessId, 3000))
                    Log(L"[!] 子进程 hook 就绪等待超时（PID=%lu），照常放行",
                        lpProcessInformation->dwProcessId);
            } else {
                Log(L"[!] 子进程注入未成功（PID=%lu）：跳过就绪等待",
                    lpProcessInformation->dwProcessId);
            }
            if (!callerWantsSuspend) {
                ResumeChildMainThread(lpProcessInformation->dwProcessId,
                                      lpProcessInformation->hThread);
            }
            // 调用方本来就要挂起则不恢复，由调用方自行 ResumeThread
        } catch (...) {
            // catch 内用不分配、不抛出的 LogFallback：异常处理器自身不得再抛
            LogFallback(L"[!] CreateProcessW 传播段异常，best-effort 恢复主线程");
            if (!callerWantsSuspend)
                ResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

static BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    const BOOL callerWantsSuspend = (dwCreationFlags & CREATE_SUSPENDED) ? TRUE : FALSE;
    // 同 CreateProcessW 版：仅在确定要注入时才追加挂起标志
    const bool inject = g_injectChildren && lpProcessInformation != nullptr;
    BOOL ok = g_realCreateProcessA(lpApplicationName, lpCommandLine,
                                   lpProcessAttributes, lpThreadAttributes,
                                   bInheritHandles,
                                   dwCreationFlags | (inject ? CREATE_SUSPENDED : 0),
                                   lpEnvironment, lpCurrentDirectory, lpStartupInfo,
                                   lpProcessInformation);
    if (ok && inject) {
        // 异常边界语义同 CreateProcessW 版
        try {
            Log(L"CreateProcessA：子进程 PID=%lu，传播注入", lpProcessInformation->dwProcessId);
            // 策略同 CreateProcessW 版
            if (InjectSelf(lpProcessInformation->hProcess, lpProcessInformation->dwProcessId)) {
                if (!WaitForHookReady(lpProcessInformation->dwProcessId, 3000))
                    Log(L"[!] 子进程 hook 就绪等待超时（PID=%lu），照常放行",
                        lpProcessInformation->dwProcessId);
            } else {
                Log(L"[!] 子进程注入未成功（PID=%lu）：跳过就绪等待",
                    lpProcessInformation->dwProcessId);
            }
            if (!callerWantsSuspend) {
                ResumeChildMainThread(lpProcessInformation->dwProcessId,
                                      lpProcessInformation->hThread);
            }
        } catch (...) {
            // catch 内用不分配、不抛出的 LogFallback，同 CreateProcessW 版
            LogFallback(L"[!] CreateProcessA 传播段异常，best-effort 恢复主线程");
            if (!callerWantsSuspend)
                ResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

// ----------------------------------------------------------------------------
// 安装线程：配置 -> MinHook 初始化 -> 建 hook -> 启用 -> 置位就绪事件
// ----------------------------------------------------------------------------

// 安装流程独立成静态函数，便于入口统一加异常边界
static DWORD InstallThreadBody(LPVOID /*param*/)
{
    // 1. 配置先行：决定日志开关与覆写规则
    LoadConfig();

    // 2. 初始化 MinHook
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        Log(L"[!] MH_Initialize 失败：%d", static_cast<int>(st));
        return 1;
    }

    // 3. 确保目标模块已加载，再取导出地址（提前失败也要与 MH_Initialize
    //    配对反初始化，不留半初始化状态）
    HMODULE combase = LoadLibraryW(L"combase.dll");
    if (!combase) {
        Log(L"[!] 加载 combase.dll 失败");
        MH_STATUS u = MH_Uninitialize();
        if (u != MH_OK)
            LogFallback(L"[!] MH_Uninitialize 失败：%d", static_cast<int>(u));
        return 1;
    }
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        Log(L"[!] 获取 kernel32.dll 句柄失败");
        MH_STATUS u = MH_Uninitialize();
        if (u != MH_OK)
            LogFallback(L"[!] MH_Uninitialize 失败：%d", static_cast<int>(u));
        return 1;
    }

    struct HookEntry {
        const char* name;
        void* target;
        void* detour;
        void** original;
        bool required; // WMI hook 恒必需；CreateProcess hook 仅传播开启时必需
    };
    HookEntry entries[] = {
        { "CoCreateInstance",
          reinterpret_cast<void*>(GetProcAddress(combase, "CoCreateInstance")),
          reinterpret_cast<void*>(&Hooked_CoCreateInstance),
          reinterpret_cast<void**>(&g_realCoCreateInstance),
          true },
        { "CoCreateInstanceEx",
          reinterpret_cast<void*>(GetProcAddress(combase, "CoCreateInstanceEx")),
          reinterpret_cast<void*>(&Hooked_CoCreateInstanceEx),
          reinterpret_cast<void**>(&g_realCoCreateInstanceEx),
          true },
        { "CreateProcessW",
          reinterpret_cast<void*>(GetProcAddress(k32, "CreateProcessW")),
          reinterpret_cast<void*>(&Hooked_CreateProcessW),
          reinterpret_cast<void**>(&g_realCreateProcessW),
          g_injectChildren },
        { "CreateProcessA",
          reinterpret_cast<void*>(GetProcAddress(k32, "CreateProcessA")),
          reinterpret_cast<void*>(&Hooked_CreateProcessA),
          reinterpret_cast<void**>(&g_realCreateProcessA),
          g_injectChildren },
    };

    // 4. 逐个创建 hook：必需 hook 失败 = 致命（本轮结束后整体回滚、不置位
    //    就绪事件）；可选 hook 失败只降级记录。逐项记录实际创建明细。
    bool fatal = false;
    int created = 0;
    for (const HookEntry& e : entries) {
        if (!e.target) {
            Log(L"[!] 未找到导出函数 %hs%s", e.name,
                e.required ? L"（必需）" : L"（可选，跳过）");
            if (e.required)
                fatal = true;
            continue;
        }
        if (e.required && FaultEnabled(L"createhook")) {
            Log(L"[fault] 模拟 MH_CreateHook(%hs) 失败", e.name);
            fatal = true;
            continue;
        }
        MH_STATUS s = MH_CreateHook(e.target, e.detour, e.original);
        if (s != MH_OK) {
            Log(L"[!] MH_CreateHook(%hs) 失败：%d%s", e.name, static_cast<int>(s),
                e.required ? L"（必需）" : L"（可选，跳过）");
            if (e.required)
                fatal = true;
            continue;
        }
        Log(L"hook 已创建：%hs", e.name);
        ++created;
    }

    if (fatal) {
        Log(L"[!] 必需 hook 创建失败：回滚全部 hook（MH_Uninitialize），不置位就绪事件");
        // 内部禁用并移除全部已创建 hook，不留半启用状态（失败不得宣称回滚完成）
        MH_STATUS u = MH_Uninitialize();
        if (u != MH_OK)
            LogFallback(L"[!] MH_Uninitialize 回滚失败：%d（宿主重启前 hook 状态未定）",
                        static_cast<int>(u));
        return 1;
    }

    // 5. 一键启用；全部必需 hook 就位且启用成功才置位就绪事件（等待方以此判定生效）
    MH_STATUS st2;
    if (FaultEnabled(L"enable")) {
        Log(L"[fault] 模拟 MH_EnableHook 失败");
        st2 = MH_ERROR_MEMORY_PROTECT;
    } else {
        st2 = MH_EnableHook(MH_ALL_HOOKS);
    }
    if (st2 != MH_OK) {
        // MinHook 批量启用失败即中断，已启用的前序 hook 不会自动撤销——统一回滚
        Log(L"[!] MH_EnableHook 失败：%d（已创建 %d 个）：回滚全部 hook，不置位就绪事件",
            static_cast<int>(st2), created);
        MH_STATUS u = MH_Uninitialize(); // 失败不得宣称回滚完成
        if (u != MH_OK)
            LogFallback(L"[!] MH_Uninitialize 回滚失败：%d（宿主重启前 hook 状态未定）",
                        static_cast<int>(u));
        return 1;
    }
    Log(L"hook 全部启用成功（共 %d 个，必需项全部就位；明细见上方逐项记录）", created);
    SignalHookReady();
    return 0;
}

// 线程入口（dllmain CreateThread 引用）：线程函数也是外部边界——InstallThreadBody
// 中的配置解析/字符串分配在内存不足时会抛出，异常越过线程边界即 std::terminate
// 杀死宿主进程。拦截后返回 1 = 安装失败、不置位就绪事件（与必需 hook 失败语义一致：
// launcher 报"未确认"，宿主放行真实行为）
DWORD WINAPI InstallThread(LPVOID param)
{
    try {
        return InstallThreadBody(param);
    } catch (...) {
        LogFallback(L"[!] 安装线程异常被拦截：不置位就绪事件，放行真实行为");
        return 1;
    }
}
