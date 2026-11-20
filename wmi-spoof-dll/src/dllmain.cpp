// ============================================================================
//  wmi-spoofer.dll —— 进程内 WMI 指纹伪装（DllMain 入口）
//
//  原理：
//    用 MinHook 挂住本进程 combase.dll 的 CoCreateInstance / CoCreateInstanceEx。
//    当本进程内有代码请求 CLSID_WbemLocator（IID_IWbemLocator）时，把返回的
//    接口替换为代理对象：
//      CWbemLocatorProxy  —— 包装 ConnectServer，把真实 IWbemServices 再包一层
//      CWbemServicesProxy —— 其余方法原样转发，三个同步读路径按注入环境变量
//                            （WMI_SPOOFER_*）覆写后返回：
//                            · ExecQuery / CreateInstanceEnum：抽干真实枚举器，
//                              逐对象覆写，用自制回放枚举器 CReplayEnum 替代返回；
//                              回放枚举器聚合 FTM，跨单元封送仍由本对象应答；
//                            · GetObject：仅实例对象（路径含 '='）在内存副本上覆写；
//                            *Async 变体不覆写。另实现 IClientSecurity 并委托到
//                            真实代理，修复 .NET/WMI 消费者在本包装上
//                            CoSetProxyBlanket 失败导致的绑定失败；封送经显式
//                            IMarshal 转发到真实代理（unmarshal 出真实对象）。
//      ConnectServer 的 blanket 重设仅在调用方未提供凭据时进行（凭据条件化）。
//    CreateProcessW/A 仅在 WMI_SPOOFER_CHILDREN=1 时用于向子进程传播注入
//    （兼容 PyInstaller onefile：真实 Python 逻辑运行在子进程中）。
//
//  影响范围：仅被注入的进程。不修改系统、注册表、WMI 服务；
//            其他程序查到的仍是真实值；进程退出即失效。
//
//  注入参数由启动器随 CreateProcessW 以环境变量下发（见 config.cpp LoadConfig），
//  日志 wmi-spoofer.log 与本 DLL 同目录。
//
//  翻译单元划分（本轮拆分，行为与原单文件版本一致）：
//    log.cpp        日志与路径（Log / MaskValue / BuildPaths / LogInit）
//    config.cpp     注入参数解析（环境变量 -> g_rules 规则表）
//    parse.cpp      WQL / 对象路径解析（纯逻辑，tests 可单测）
//    replay_enum.h  回放枚举器 CReplayEnum（FTM 聚合）
//    proxies.h      WMI COM 代理层（SpoofObject / SpoofRealEnum / 三个包装类）
//    inject.cpp     子进程注入 + hook 就绪握手
//    hooks.cpp      MinHook hook 函数与安装线程
//    dllmain.cpp    DllMain（本文件）
// ============================================================================

#include <windows.h>

#include "hooks.h"
#include "log.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "advapi32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID /*lpReserved*/)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        BuildPaths(hModule);            // 保存 DLL 完整路径，供子进程注入使用
        LogInit();                      // 初始化日志写入互斥（先于一切 Log 调用）
        // 自钉：装好 hook 后跳板指向本模块代码，宿主任何 FreeLibrary 必须
        // 成为 no-op，否则 hook 仍在而代码已被卸载——跳入未映射内存致宿主崩溃。
        // PIN 把本模块引用计数永久 +1：生命周期 = 进程生命周期（README 支持矩阵声明）。
        {
            HMODULE pinned = nullptr;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_PIN,
                                    reinterpret_cast<LPCWSTR>(hModule), &pinned)) {
                Log(L"[!] 模块自钉失败：%lu（拒绝装 hook，避免卸载后跳板悬空）",
                    GetLastError());
                return TRUE; // 放行全部真实行为：宁可不伪装，不可崩溃
            }
        }
        // 不在 DllMain 里装 hook（loader lock 限制），交给安装线程
        {
            HANDLE h = CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
            if (h)
                CloseHandle(h);
            else
                Log(L"[!] 创建安装线程失败");
        }
        break;
    case DLL_PROCESS_DETACH:
        // 模块已自钉（见 ATTACH），正常路径不会走到卸载；进程退出随进程整体失效
        break;
    }
    return TRUE;
}
