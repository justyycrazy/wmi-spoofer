// childtest.cpp —— C2 回归验证目标（子进程传播开关闭合的行为对照）
//
// 用途：注入后（WMI_SPOOFER_CHILDREN=0），本程序用 CreateProcessW 创建自身子进程
// 并等待其退出码 7。
//   旧版 DLL 缺陷：hook 无条件给子进程追加 CREATE_SUSPENDED 且永不恢复
//   -> 子进程被永久挂起 -> 本程序永远等待 -> 结果文件永不出现。
//   修复后（仅注入时才挂起）-> 子进程正常退出 -> 结果文件写入 OK。
//
// 用法：childtest.exe <结果文件路径>
//   父模式：创建自身子进程（参数 child）并等待；退出码 7 -> 写 OK、exit 0。
//   child 模式：childtest.exe child -> 立即 exit 7。
//
// 构建（x64 Native Tools 环境）：
//   cl /O2 /EHsc /std:c++17 /utf-8 tools\childtest.cpp /Fe:tools\childtest.exe
#include <windows.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv)
{
    if (argc >= 2 && strcmp(argv[1], "child") == 0)
        return 7; // 子进程模式：立即退出码 7（父进程等待此值）

    const char* resultFile = (argc >= 2) ? argv[1] : "childtest-result.txt";

    char self[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    char cmd[MAX_PATH + 16] = { 0 };
    snprintf(cmd, sizeof(cmd), "\"%s\" child", self);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                        &si, &pi)) {
        printf("CreateProcess failed %lu\n", GetLastError());
        return 1;
    }

    DWORD w = WaitForSingleObject(pi.hProcess, 15000);
    int rc = 1;
    if (w == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        if (code == 7) {
            HANDLE h = CreateFileA(resultFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD wrote = 0;
                WriteFile(h, "OK", 2, &wrote, nullptr);
                CloseHandle(h);
            }
            rc = 0;
        } else {
            printf("child exited %lu (expected 7)\n", code);
        }
    } else {
        printf("wait failed/timeout w=%lu (child likely suspended)\n", w);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}
