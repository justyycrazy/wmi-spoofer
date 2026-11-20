// bench-wmi.cpp —— M8 热路径开销测量探针
//
// 目的：量化注入对 WMI 查询的实际延迟影响（DLL 抽干 + 覆写 + 逐行日志 IO 的合计成本），
// 为"是否需要降噪优化"提供测量依据（判据见 README 排障/限制节）。
//
// 方法：两类查询各循环 N 次（默认 200），QueryPerformanceCounter 计时取平均值。
//   PASS 类：SELECT * FROM Win32_ComputerSystem —— 非规则类，注入后原样转发（纯 hook 开销）
//   HIT  类：SELECT * FROM Win32_Processor     —— 规则命中类，含抽干+覆写+日志全成本
// 对比注入前/后同机各跑一次：延迟增幅 = (注入后-基线)/基线。
// 注意：注入后 PAS 类日志仍有"ExecQuery: …"一行（未命中也记录），HIT 类另有抽干与 Put 记录。
//
// 用法：bench-wmi.exe [迭代次数，默认 200]
// 输出：AVG_US_PASS=<x> AVG_US_HIT=<x>（微秒/次）；注入前后各跑一次后人工对照。
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <cstdio>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static double BenchQuery(IWbemServices* svc, const wchar_t* wql, int iterations)
{
    BSTR lang = SysAllocString(L"WQL");
    BSTR stmt = SysAllocString(wql);
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iterations; ++i) {
        IEnumWbemClassObject* en = nullptr;
        HRESULT hr = svc->ExecQuery(lang, stmt, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
        if (FAILED(hr) || !en) {
            wprintf(L"    ExecQuery failed hr=0x%08X (iter %d)\n",
                    static_cast<unsigned>(hr), i);
            continue;
        }
        for (;;) {
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            HRESULT h = en->Next(5000, 1, &obj, &ret);
            if (h != WBEM_S_NO_ERROR || ret == 0 || !obj)
                break;
            obj->Release();
        }
        en->Release();
    }
    QueryPerformanceCounter(&t1);
    SysFreeString(lang);
    SysFreeString(stmt);
    return (static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000000.0) /
           static_cast<double>(freq.QuadPart) / static_cast<double>(iterations);
}

int main(int argc, char** argv)
{
    int iterations = (argc >= 2) ? atoi(argv[1]) : 200;
    if (iterations < 1)
        iterations = 1;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        return 1;
    }
    IWbemLocator* loc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    if (FAILED(hr)) {
        wprintf(L"CoCreateInstance hr=0x%08X\n", static_cast<unsigned>(hr));
        return 1;
    }
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    loc->Release();
    if (FAILED(hr) || !svc) {
        wprintf(L"ConnectServer hr=0x%08X\n", static_cast<unsigned>(hr));
        return 1;
    }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                      RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_DEFAULT);

    wprintf(L"ITERS=%d\n", iterations);
    wprintf(L"AVG_US_PASS=%.0f\n",
            BenchQuery(svc, L"SELECT * FROM Win32_ComputerSystem", iterations));
    wprintf(L"AVG_US_HIT=%.0f\n",
            BenchQuery(svc, L"SELECT * FROM Win32_Processor", iterations));
    svc->Release();
    CoUninitialize();
    return 0;
}
