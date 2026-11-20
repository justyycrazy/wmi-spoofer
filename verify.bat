@echo off
rem ============================================================
rem  One-shot local verification: build DLL + pure tests + probes,
rem  then rust fmt/clippy/tests.
rem  Usage: verify.bat            full run (rust + C++)
rem         verify.bat norust     C++ only
rem  MSVC env: auto-located via vswhere; cl must end up on PATH.
rem  This file is ASCII-only (the GBK build_msvc.bat stays untouched).
rem ============================================================
setlocal
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
)
if defined VSPATH (
    call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
)
where cl >nul 2>nul
if errorlevel 1 (echo CL_NOT_ON_PATH & exit /b 1)
where rc >nul 2>nul
if errorlevel 1 (echo RC_NOT_ON_PATH & exit /b 1)

rem ---- build DLL (with version resource) ----
if not exist wmi-spoof-dll\build mkdir wmi-spoof-dll\build
rc /nologo /fo wmi-spoof-dll\build\version.res wmi-spoof-dll\src\version.rc
if errorlevel 1 (echo RC_FAILED & exit /b 1)
cl /nologo /LD /O2 /MT /EHsc /std:c++17 /utf-8 /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE ^
   wmi-spoof-dll\src\dllmain.cpp wmi-spoof-dll\src\hooks.cpp wmi-spoof-dll\src\log.cpp ^
   wmi-spoof-dll\src\config.cpp wmi-spoof-dll\src\parse.cpp wmi-spoof-dll\src\inject.cpp ^
   wmi-spoof-dll\minhook\src\buffer.c wmi-spoof-dll\minhook\src\hook.c ^
   wmi-spoof-dll\minhook\src\trampoline.c wmi-spoof-dll\minhook\src\hde\hde64.c ^
   /I wmi-spoof-dll\minhook\include ^
   /Fe:wmi-spoof-dll\wmi-spoofer.dll /Fo:wmi-spoof-dll\build\ ^
   /link wbemuuid.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib wmi-spoof-dll\build\version.res
if errorlevel 1 (echo DLL_BUILD_FAILED & exit /b 1)
echo [OK] DLL built

rem ---- build + run pure-function unit tests ----
if not exist wmi-spoof-dll\build\tests mkdir wmi-spoof-dll\build\tests
cl /nologo /MT /EHsc /std:c++17 /utf-8 /I wmi-spoof-dll\src ^
   wmi-spoof-dll\tests\test_pure.cpp wmi-spoof-dll\src\parse.cpp ^
   wmi-spoof-dll\src\config.cpp wmi-spoof-dll\src\log.cpp ^
   /Fe:wmi-spoof-dll\tests\test_pure.exe /Fo:wmi-spoof-dll\build\tests\ ^
   /link wbemuuid.lib ole32.lib oleaut32.lib
if errorlevel 1 (echo TESTS_BUILD_FAILED & exit /b 1)
wmi-spoof-dll\tests\test_pure.exe
if errorlevel 1 (echo TESTS_FAILED & exit /b 1)
echo [OK] pure tests passed

rem ---- build probes (wmitest / childtest / bench / apartment / blanket) ----
rem Products go to a clean dir build\probes: no stale binaries reused,
rem per-probe errorlevel is checked so a compile failure fails the whole run.
if exist wmi-spoof-dll\build\probes rmdir /s /q wmi-spoof-dll\build\probes
if not exist wmi-spoof-dll\build\probes mkdir wmi-spoof-dll\build\probes
for %%t in (wmitest childtest bench-wmi probe-apartment probe-blanket) do (
    if exist wmi-spoof-dll\tools\%%t.cpp (
        cl /nologo /MT /O2 /EHsc /std:c++17 /utf-8 wmi-spoof-dll\tools\%%t.cpp ^
           /Fe:wmi-spoof-dll\build\probes\%%t.exe /Fo:wmi-spoof-dll\build\probes\ ^
           /link wbemuuid.lib ole32.lib oleaut32.lib >nul 2>&1
        if errorlevel 1 (echo PROBE_BUILD_FAILED %%t & exit /b 1)
    )
)
wmi-spoof-dll\build\probes\childtest.exe "%TEMP%\childtest-local.txt"
if errorlevel 1 (echo CHILDTEST_FAILED & exit /b 1)
rem Use the absolute path to system find: a bare find resolves to GNU find
rem under Git Bash environments and breaks the semantics.
%SystemRoot%\System32\find.exe "OK" "%TEMP%\childtest-local.txt" >nul
if errorlevel 1 (echo CHILDTEST_NO_OK & exit /b 1)
echo [OK] probes built

rem ---- rust checks ----
if /i "%1"=="norust" goto :done
cd launcher
cargo fmt --check
if errorlevel 1 (echo FMT_FAILED & exit /b 1)
cargo clippy --all-targets -- -D warnings
if errorlevel 1 (echo CLIPPY_FAILED & exit /b 1)
cargo test
if errorlevel 1 (echo CARGO_TEST_FAILED & exit /b 1)
echo [OK] rust checks passed
cd ..

:done
echo ALL_OK
endlocal
