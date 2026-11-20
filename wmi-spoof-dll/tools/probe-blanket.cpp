// probe-blanket.cpp —— 显式凭据探针：ConnectServer 显式凭据 vs DLL 的 blanket 重设
//
// 背景：wmi-spoofer.dll 的 CWbemLocatorProxy::ConnectServer 成功后按凭据条件化
// 策略处理真实 services 代理——仅当调用方未提供 strUser/strPassword 时才执行
// CoSetProxyBlanket(IMPERSONATE)，带凭据连接不重设（避免覆盖调用方凭据）。本探针
// 实证/回归：显式凭据连接下，注入前后凭据状态与查询行为是否被注入改变。
//
// 用法：
//   probe-blanket.exe credcheck   用虚构错误凭据连 \\localhost\ROOT\CIMV2，判定本地连接
//                                 是否校验显式凭据（不需要任何真实凭据）
//   probe-blanket.exe withcred    用环境变量 WMI_SPOOF_PROBE_USER / WMI_SPOOF_PROBE_PASS
//                                 提供的真实凭据连 \\localhost\ROOT\CIMV2：打印连接/查询 hr、
//                                 读到的值与 CoQueryProxyBlanket 读回字段，供注入前后对照
//
// 凭据纪律：凭据只经环境变量进入本进程内存；不写盘、不打印（输出只显示 len=N）；
// 用完 SecureZeroMemory 清零 BSTR 数据区与环境变量缓冲。
//
// 判定口径（注入前后各跑一次对照）：
//   credcheck 仍成功   = 本地连接忽略显式凭据，本环境构造不出带凭据连接成功
//                        的场景（如实标注）；
//   credcheck 被拒     = 本地凭据可校验，可进入 withcred（127.0.0.1 回环可模拟
//                        远程语义，见下方 server 参数说明）；
//   withcred 注入前后查询均成功、QueryBlanket 读回字段一致
//                      = 凭据条件化生效：带凭据连接未被重设（现版预期）；
//   注入后查询失败（ACCESS_DENIED 等）或读回字段变化
//                      = 回归：blanket 重设错误作用于带凭据代理。
//
// 构建：cl /O2 /EHsc /std:c++17 /utf-8 tools\probe-blanket.cpp /Fe:tools\probe-blanket.exe
//       /Fo:tools\ /link wbemuuid.lib ole32.lib oleaut32.lib
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ----------------------------------------------------------------------------
// 公共
// ----------------------------------------------------------------------------

// 由服务器名构造命名空间串：\\<server>\ROOT\CIMV2。缺省 localhost。
// server 可传 127.0.0.1 等"本机回环模拟远程"目标（localhost/机器名走本地路径时
// WMI 直接拒绝显式凭据：WBEM_E_LOCAL_CREDENTIALS 0x80041064）。
static std::wstring MakeNamespace(const char* server)
{
    std::wstring s;
    if (server && *server) {
        int n = MultiByteToWideChar(CP_UTF8, 0, server, -1, nullptr, 0);
        if (n > 0) {
            std::vector<wchar_t> buf(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, server, -1, buf.data(), n);
            s = buf.data();
        }
    }
    if (s.empty())
        s = L"localhost";
    return L"\\\\" + s + L"\\ROOT\\CIMV2";
}

// 读环境变量到缓冲（含结尾 NUL）；不存在或超长返回 false
static bool ReadEnvWide(const wchar_t* name, std::vector<wchar_t>& buf)
{
    DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0 || n > 4096)
        return false;
    buf.assign(n, L'\0');
    GetEnvironmentVariableW(name, buf.data(), n);
    return true;
}

// 清零 BSTR 数据区后再释放（凭据内存纪律：不依赖堆回收）
static void SecureFreeBstr(BSTR& bs)
{
    if (bs) {
        unsigned bytes = SysStringByteLen(bs);
        if (bytes)
            SecureZeroMemory(bs, bytes);
        SysFreeString(bs);
        bs = nullptr;
    }
}

// 三条指纹查询（与 tools/wmitest.cpp / probe-apartment.cpp 口径一致）
static void RunFingerprintQueries(IWbemServices* svc)
{
    struct Q { const wchar_t* wql; const wchar_t* prop; };
    const Q qs[] = {
        { L"SELECT * FROM Win32_Processor", L"ProcessorId" },
        { L"SELECT * FROM Win32_BaseBoard", L"SerialNumber" },
        { L"SELECT * FROM Win32_DiskDrive WHERE MediaType = 'Fixed hard disk media'",
          L"SerialNumber" },
    };
    for (const Q& q : qs) {
        BSTR lang = SysAllocString(L"WQL");
        BSTR stmt = SysAllocString(q.wql);
        IEnumWbemClassObject* en = nullptr;
        HRESULT hr = svc->ExecQuery(lang, stmt, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
        SysFreeString(lang);
        SysFreeString(stmt);
        wprintf(L"    ExecQuery hr=0x%08X [%s]\n", static_cast<unsigned>(hr), q.wql);
        if (FAILED(hr) || !en)
            continue;
        for (;;) {
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            HRESULT h = en->Next(5000, 1, &obj, &ret);
            if (h != WBEM_S_NO_ERROR || ret == 0 || !obj) {
                wprintf(L"      Next end h=0x%08X ret=%u\n", static_cast<unsigned>(h), ret);
                break;
            }
            VARIANT v;
            VariantInit(&v);
            if (SUCCEEDED(obj->Get(q.prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
                wprintf(L"      %s = %s\n", q.prop, v.bstrVal);
            else
                wprintf(L"      %s = (read failed or non-BSTR)\n", q.prop);
            VariantClear(&v);
            obj->Release();
        }
        en->Release();
    }
}

// 读回并打印代理安全毯状态（serverPrincName 由 CoTaskMemFree 释放）。
// 注入后该调用落在包装实现的 IClientSecurity 上，委托真实代理——读回即真实状态。
static void PrintBlanket(IWbemServices* svc, const char* tag)
{
    DWORD authnSvc = 0, authzSvc = 0, authnLvl = 0, impLvl = 0, caps = 0;
    OLECHAR* princ = nullptr;
    HRESULT hr = CoQueryProxyBlanket(svc, &authnSvc, &authzSvc, &princ,
                                     &authnLvl, &impLvl, nullptr, &caps);
    if (SUCCEEDED(hr)) {
        wprintf(L"    %hs CoQueryProxyBlanket hr=0x%08X authnSvc=%lu authzSvc=%lu "
                L"princ=%s authnLvl=%lu impLvl=%lu caps=0x%08lX\n",
                tag, static_cast<unsigned>(hr), authnSvc, authzSvc,
                (princ ? princ : L"(null)"), authnLvl, impLvl, caps);
        if (princ)
            CoTaskMemFree(princ);
    } else {
        wprintf(L"    %hs CoQueryProxyBlanket hr=0x%08X\n", tag, static_cast<unsigned>(hr));
    }
}

// ----------------------------------------------------------------------------
// 阶段 0：credcheck（虚构错误凭据，判定本地连接是否校验显式凭据）
// ----------------------------------------------------------------------------

static int CredCheck(const char* server)
{
    std::wstring nsStr = MakeNamespace(server);
    wprintf(L"=== credcheck: bogus credentials vs %s ===\n", nsStr.c_str());
    HRESULT hrI = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hrI)) {
        wprintf(L"    CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hrI));
        return 1;
    }
    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    if (FAILED(hr) || !loc) {
        wprintf(L"    CoCreateInstance hr=0x%08X\n", static_cast<unsigned>(hr));
        CoUninitialize();
        return 1;
    }
    BSTR ns = SysAllocString(nsStr.c_str());
    BSTR u   = SysAllocString(L"__wmi_probe_no_such_user__");
    BSTR p   = SysAllocString(L"__wmi_probe_wrong_password__");
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(ns, u, p, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    SysFreeString(u);
    SysFreeString(p);
    if (SUCCEEDED(hr) && svc) {
        wprintf(L"    ConnectServer(bogus user/pass) hr=0x%08X\n", static_cast<unsigned>(hr));
        wprintf(L"    => connection SUCCEEDED with bogus credentials (ignored/expired);\n");
        wprintf(L"    => explicit-credential overwrite NOT testable with this target.\n");
        svc->Release();
    } else if (hr == 0x80041064) { // WBEM_E_LOCAL_CREDENTIALS
        wprintf(L"    ConnectServer(bogus user/pass) hr=0x%08X (WBEM_E_LOCAL_CREDENTIALS)\n",
                static_cast<unsigned>(hr));
        wprintf(L"    => local namespace path REJECTS explicit credentials outright;\n");
        wprintf(L"    => try loopback (127.0.0.1) to emulate a remote connection.\n");
    } else {
        wprintf(L"    ConnectServer(bogus user/pass) hr=0x%08X\n", static_cast<unsigned>(hr));
        wprintf(L"    => credentials are VALIDATED at connect stage (remote semantics);\n");
        wprintf(L"    => explicit-credential overwrite IS testable with this target using valid credentials.\n");
    }
    loc->Release();
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 阶段 1：withcred（真实凭据经环境变量进入；不打印不落盘）
// ----------------------------------------------------------------------------

static int WithCred(const char* server)
{
    std::wstring nsStr = MakeNamespace(server);
    wprintf(L"=== withcred: env credentials vs %s ===\n", nsStr.c_str());
    std::vector<wchar_t> ub, pb;
    bool hasU = ReadEnvWide(L"WMI_SPOOF_PROBE_USER", ub);
    bool hasP = ReadEnvWide(L"WMI_SPOOF_PROBE_PASS", pb);
    if (!hasU || !hasP) {
        wprintf(L"    WMI_SPOOF_PROBE_USER / WMI_SPOOF_PROBE_PASS not set or invalid\n");
        return 1;
    }
    size_t ulen = wcslen(ub.data());
    size_t plen = wcslen(pb.data());
    wprintf(L"    credentials provided: user len=%zu pass len=%zu (values never printed)\n",
            ulen, plen);

    HRESULT hrI = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hrI)) {
        wprintf(L"    CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hrI));
        return 1;
    }
    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    if (FAILED(hr) || !loc) {
        wprintf(L"    CoCreateInstance hr=0x%08X\n", static_cast<unsigned>(hr));
        CoUninitialize();
        return 1;
    }

    BSTR ns = SysAllocString(nsStr.c_str());
    BSTR u   = SysAllocString(ub.data());
    BSTR p   = SysAllocString(pb.data());
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(ns, u, p, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    SecureFreeBstr(u);
    SecureFreeBstr(p);
    SecureZeroMemory(ub.data(), ub.size() * sizeof(wchar_t));
    SecureZeroMemory(pb.data(), pb.size() * sizeof(wchar_t));
    wprintf(L"    ConnectServer hr=0x%08X\n", static_cast<unsigned>(hr));
    if (FAILED(hr) || !svc) {
        wprintf(L"    => connect failed (credential rejected at connect stage)\n");
        loc->Release();
        CoUninitialize();
        return 0;
    }

    // 不做任何 CoSetProxyBlanket：探针只观察连接方返回的代理状态。
    // 注入后 ConnectServer 落在包装上，DLL 的 blanket 重设（凭据条件化：带凭据
    // 连接不重设）发生在返回之前，此处读回的即是 DLL 处理后的状态（对照注入前）。
    PrintBlanket(svc, "after-connect");
    RunFingerprintQueries(svc);
    PrintBlanket(svc, "after-query");

    svc->Release();
    loc->Release();
    CoUninitialize();
    return 0;
}

int main(int argc, char** argv)
{
    // argv[2] 可选：服务器名（缺省 localhost）。本机回环模拟远程可传 127.0.0.1。
    const char* server = (argc >= 3) ? argv[2] : nullptr;
    if (argc >= 2 && _stricmp(argv[1], "credcheck") == 0)
        return CredCheck(server);
    if (argc >= 2 && _stricmp(argv[1], "withcred") == 0)
        return WithCred(server);
    wprintf(L"usage: probe-blanket.exe credcheck [server] | withcred [server]\n");
    return 1;
}
