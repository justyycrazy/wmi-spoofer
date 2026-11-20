// ============================================================================
//  log.cpp —— 日志与路径实现
// ============================================================================
#include "log.h"

#include "common.h"

#include <cstdarg>
#include <cstring>
#include <memory>
#include <string>

wchar_t g_dllPath[MAX_PATH] = { 0 }; // 本 DLL 完整路径（DllMain 保存，供子进程注入使用）
wchar_t g_logPath[MAX_PATH] = { 0 }; // 同目录 wmi-spoofer.log

static CRITICAL_SECTION g_logCs; // 日志写入互斥

void LogInit()
{
    InitializeCriticalSection(&g_logCs);
}

// 由 DLL 自身路径推导出同目录下的 log 路径。
// 路径异常（获取失败/过长）时安全降级，绝不让 wcscpy_s 触发 CRT
// invalid parameter handler（其默认行为是终止宿主进程）。
void BuildPaths(HMODULE hSelf)
{
    wchar_t self[MAX_PATH] = { 0 };
    DWORD n = GetModuleFileNameW(hSelf, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        g_dllPath[0] = L'\0';
        g_logPath[0] = L'\0';
        g_injectChildren = false; // 自身路径未知，绝不用坏路径注入子进程
        return;
    }
    wcscpy_s(g_dllPath, MAX_PATH, self);

    std::wstring dir(self);
    size_t pos = dir.find_last_of(L"\\/");
    dir = (pos == std::wstring::npos) ? L"" : dir.substr(0, pos + 1);

    if (dir.size() + wcslen(L"wmi-spoofer.log") + 1 > MAX_PATH) {
        g_logPath[0] = L'\0'; // 仅禁日志；注入路径仍有效
        return;
    }
    wcscpy_s(g_logPath, MAX_PATH, (dir + L"wmi-spoofer.log").c_str());
}

// 日志大小上限：超过即删除重建（轮转），防止长期运行的目标进程日志无限增长
static const long long kLogMaxBytes = 2 * 1024 * 1024;

// 追加 UTF-8 字节到日志文件（含 2MB 轮转），内部持锁。
// Log 与 LogFallback 共用；多进程并发轮转存在竞态，可接受：
// 最坏情形是一方刚删、另一方写入的一行丢失
static void AppendUtf8(const char* data, size_t len)
{
    EnterCriticalSection(&g_logCs);
    HANDLE h = CreateFileW(g_logPath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz;
        if (GetFileSizeEx(h, &sz) && sz.QuadPart >= kLogMaxBytes) {
            CloseHandle(h);
            DeleteFileW(g_logPath);
            h = CreateFileW(g_logPath, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                const char marker[] = "[log rotated: exceeded 2MB]\r\n";
                DWORD mw = 0;
                WriteFile(h, marker, sizeof(marker) - 1, &mw, nullptr);
            }
        }
        if (h != INVALID_HANDLE_VALUE) {
            SetFilePointer(h, 0, nullptr, FILE_END);
            DWORD written = 0;
            WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr);
            CloseHandle(h);
        }
    }
    LeaveCriticalSection(&g_logCs);
}

// 追加一行 UTF-8 日志（多进程并发追加：以共享写方式打开文件尾部）。
// 异常安全——UTF-8 转换缓冲改用 nothrow new（有堆分配，但分配
// 失败不抛出），OOM 时静默丢行（noexcept 契约见 log.h），边界外的调用点因此
// 无需自备防护
void Log(const wchar_t* fmt, ...) noexcept
{
    if (!g_logEnabled || !g_logPath[0]) // 路径不可用时静默禁用（BuildPaths 降级）
        return;

    wchar_t msg[2048];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msg, _TRUNCATE, fmt, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[2304];
    _snwprintf_s(line, _TRUNCATE, L"[%02u:%02u:%02u.%03u] %s\r\n",
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);

    // 统一转 UTF-8 写入，避免记事本/编辑器乱码
    int need = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (need <= 1)
        return;
    std::unique_ptr<char[]> buf(new (std::nothrow) char[need]);
    if (!buf)
        return; // OOM：静默丢行，绝不抛出（保持 noexcept 契约）
    WideCharToMultiByte(CP_UTF8, 0, line, -1, buf.get(), need, nullptr, nullptr);
    AppendUtf8(buf.get(), static_cast<size_t>(need) - 1);
}

// 异常处理器专用的降级日志——全程栈缓冲、无 C++ 分配、不抛出，
// 专为 catch 块设计（比 Log 紧凑：只求把要点落盘）
void LogFallback(const wchar_t* fmt, ...) noexcept
{
    if (!g_logEnabled || !g_logPath[0])
        return;

    wchar_t msg[512]; // 栈缓冲较 Log 紧凑：异常路径只求把要点落盘
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(msg, _TRUNCATE, fmt, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[768];
    _snwprintf_s(line, _TRUNCATE, L"[%02u:%02u:%02u.%03u] %s\r\n",
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);

    // 直写栈缓冲转换；放不下（极端情形）落一行固定 ASCII 占位，绝不分配
    char buf[1536];
    const char* out = buf;
    size_t len = 0;
    int need = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (need > 1 && need <= static_cast<int>(sizeof(buf))) {
        WideCharToMultiByte(CP_UTF8, 0, line, -1, buf, need, nullptr, nullptr);
        len = static_cast<size_t>(need) - 1;
    } else {
        static const char kTrunc[] = "LogFallback: message truncated\r\n";
        out = kTrunc;
        len = sizeof(kTrunc) - 1;
    }
    AppendUtf8(out, len);
}

// 值脱敏：真实硬件指纹是本工具要隐藏的数据，日志只保留首尾各 2 字符与长度。
// Put 行的假值默认同样脱敏；WMI_SPOOFER_LOG_FAKE=1 时 SpoofObject 侧
// 改记明文，用于核对 Put 是否送达。
std::wstring MaskValue(const std::wstring& v)
{
    wchar_t suffix[32];
    swprintf(suffix, 32, L"<长度%zu>", v.size());
    if (v.size() <= 4)
        return suffix;
    return v.substr(0, 2) + L"…" + v.substr(v.size() - 2) + suffix;
}
