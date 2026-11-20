@echo off
rem Build and run the pure-function unit tests (parse/config/log).
rem Run from "x64 Native Tools Command Prompt for VS". This file is ASCII-only.
setlocal
cd /d "%~dp0.."
if not exist build mkdir build
if not exist build\tests mkdir build\tests

rem /MT: statically link the CRT so the test exe has no runtime DLL dependency
cl /nologo /MT /EHsc /std:c++17 /utf-8 /I src ^
   tests\test_pure.cpp src\parse.cpp src\config.cpp src\log.cpp ^
   /Fe:tests\test_pure.exe /Fo:build\tests\ ^
   /link wbemuuid.lib ole32.lib oleaut32.lib
if errorlevel 1 (echo BUILD_FAILED & exit /b 1)

tests\test_pure.exe
if errorlevel 1 (echo TESTS_FAILED & exit /b 1)
echo TESTS_OK
endlocal
