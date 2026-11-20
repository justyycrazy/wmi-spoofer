@echo off
rem ============================================================
rem  wmi-spoofer.dll 构建脚本（MSVC）
rem  用法：在 "x64 Native Tools Command Prompt for VS" 中运行
rem  产物：wmi-spoofer.dll（x64）
rem
rem  32 位目标：改用 "x86 Native Tools Command Prompt" 运行，
rem  并把下方源文件列表中的 hde64.c 换成 hde32.c（见文件末尾注释）。
rem  注意：本文件为 GBK 编码，中文 cmd 可直接解析。
rem ============================================================
setlocal
cd /d "%~dp0"

rem MinHook 源码缺失时自动克隆（正常情况下工程内已附带 minhook\ 目录）
if not exist "minhook\include\MinHook.h" (
    echo [i] MinHook 源码缺失，正在从 GitHub 克隆...
    git clone --depth 1 --branch v1.3.4 https://github.com/TsudaKageyu/minhook
    if errorlevel 1 (
        echo [x] 克隆 MinHook 失败，请手动执行: git clone --depth 1 --branch v1.3.4 https://github.com/TsudaKageyu/minhook
        exit /b 1
    )
)

if not exist "build" mkdir build
rc /nologo /fo build\version.res src\version.rc

cl /nologo /LD /O2 /MT /EHsc /std:c++17 /utf-8 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE ^
   src\dllmain.cpp src\hooks.cpp src\log.cpp src\config.cpp src\parse.cpp src\inject.cpp ^
   minhook\src\buffer.c minhook\src\hook.c minhook\src\trampoline.c minhook\src\hde\hde64.c ^
   /I minhook\include ^
   /Fe:wmi-spoofer.dll /Fo:build\ ^
   /link wbemuuid.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib build\version.res

if errorlevel 1 (
    echo [x] 编译失败
    exit /b 1
)

echo [OK] 构建完成: %~dp0wmi-spoofer.dll
endlocal

rem ---- 32 位版本参考命令（在 x86 命令行环境中运行）----
rem cl /nologo /LD /O2 /MT /EHsc /std:c++17 /utf-8 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE src\dllmain.cpp src\hooks.cpp src\log.cpp src\config.cpp src\parse.cpp src\inject.cpp minhook\src\buffer.c minhook\src\hook.c minhook\src\trampoline.c minhook\src\hde\hde32.c /I minhook\include /Fe:wmi-spoofer.dll /Fo:build\ /link wbemuuid.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib build\version.res
