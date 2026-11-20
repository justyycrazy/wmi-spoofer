// wmitest.cpp —— 最小 WMI 消费者（注入探针：CPU / 主板 / 磁盘三类指纹查询）
// 用法：
//   wmitest.exe                  默认模式：ExecQuery 三连（与旧版行为一致，回归对照用）
//   wmitest.exe enum <类名>...   CreateInstanceEnum 路径：按类名枚举实例并打印指纹属性
//                                （覆盖 SWbemServices.InstancesOf / ManagementClass.GetInstances
//                                 所走的枚举 API，供注入前后对照）
//   wmitest.exe getobj <对象路径> GetObject 路径：取单实例并打印指纹属性
//                                （如 Win32_BaseBoard=@，覆盖脚本层 GetObject 单实例读取）
// 输出：每个查询的 hr 与读到的属性值，供 wmi-spoofer.dll 注入前后对照。
// 构建变体：/DFWD_ONLY   -> 查询带 WBEM_FLAG_FORWARD_ONLY（0x30）
//           默认          -> 仅 RETURN_IMMEDIATELY（0x10）
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <cstdio>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#ifndef QUERY_FLAGS
#ifdef FWD_ONLY
#define QUERY_FLAGS (WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY)
#else
#define QUERY_FLAGS WBEM_FLAG_RETURN_IMMEDIATELY
#endif
#endif

static void DumpOne(IWbemClassObject* obj, const wchar_t* prop)
{
    VARIANT v;
    VariantInit(&v);
    if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR)
        wprintf(L"    %s = %s\n", prop, v.bstrVal);
    else
        wprintf(L"    %s 读取失败\n", prop);
    VariantClear(&v);
}

static void Query(IWbemServices* svc, const wchar_t* wql, const wchar_t* prop)
{
    BSTR lang = SysAllocString(L"WQL");
    BSTR stmt = SysAllocString(wql);
    IEnumWbemClassObject* en = nullptr;
    HRESULT hr = svc->ExecQuery(lang, stmt, QUERY_FLAGS, nullptr, &en);
    SysFreeString(lang);
    SysFreeString(stmt);
    wprintf(L"ExecQuery hr=0x%08X flags=0x%X [%s]\n",
            static_cast<unsigned>(hr), QUERY_FLAGS, wql);
    if (FAILED(hr) || !en)
        return;
    for (;;) {
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        HRESULT h = en->Next(WBEM_INFINITE, 1, &obj, &ret);
        if (h != WBEM_S_NO_ERROR || ret == 0 || !obj) {
            wprintf(L"    Next end: h=0x%08X ret=%u\n", static_cast<unsigned>(h), ret);
            break;
        }
        DumpOne(obj, prop);
        obj->Release();
    }
    en->Release();
}

// 类名 -> 指纹属性（Win32_Processor 是 ProcessorId，其余按 SerialNumber）
static const wchar_t* FingerprintProp(const wchar_t* cls)
{
    return _wcsicmp(cls, L"Win32_Processor") == 0 ? L"ProcessorId" : L"SerialNumber";
}

// CreateInstanceEnum 路径：枚举该类全部实例，打印指纹属性（读到什么打什么）
static void EnumClass(IWbemServices* svc, const wchar_t* cls)
{
    BSTR bcls = SysAllocString(cls);
    IEnumWbemClassObject* en = nullptr;
    HRESULT hr = svc->CreateInstanceEnum(bcls, 0 /*RETURN_WBEM_COMPLETE*/,
                                         nullptr, &en);
    SysFreeString(bcls);
    wprintf(L"CreateInstanceEnum hr=0x%08X [%s]\n", static_cast<unsigned>(hr), cls);
    if (FAILED(hr) || !en)
        return;
    ULONG count = 0;
    for (;;) {
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        HRESULT h = en->Next(WBEM_INFINITE, 1, &obj, &ret);
        if (h != WBEM_S_NO_ERROR || ret == 0 || !obj) {
            wprintf(L"    Next end: h=0x%08X ret=%u (total %u)\n",
                    static_cast<unsigned>(h), ret, count);
            break;
        }
        ++count;
        DumpOne(obj, FingerprintProp(cls));
        obj->Release();
    }
    en->Release();
}

// GetObject 路径：取单个对象（实例或类定义），打印指纹属性与 __CLASS
static void GetObj(IWbemServices* svc, const wchar_t* path)
{
    BSTR bpath = SysAllocString(path);
    IWbemClassObject* obj = nullptr;
    HRESULT hr = svc->GetObject(bpath, 0, nullptr, &obj, nullptr);
    SysFreeString(bpath);
    wprintf(L"GetObject hr=0x%08X [%s]\n", static_cast<unsigned>(hr), path);
    if (FAILED(hr) || !obj)
        return;
    DumpOne(obj, L"__CLASS");
    DumpOne(obj, L"SerialNumber");
    DumpOne(obj, L"ProcessorId");
    obj->Release();
}

int main(int argc, char** argv)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { wprintf(L"CoInitializeEx hr=0x%08X\n", hr); return 1; }

    IWbemLocator* loc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    wprintf(L"CoCreateInstance hr=0x%08X\n", static_cast<unsigned>(hr));
    if (FAILED(hr)) return 1;

    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr,
                            0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    wprintf(L"ConnectServer hr=0x%08X\n", static_cast<unsigned>(hr));
    if (FAILED(hr)) return 1;
    loc->Release();

    // 经典 WMI 客户端修复：不设 IMPERSONATE 时 Next 会 ACCESS_DENIED
    hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                           RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_DEFAULT);
    wprintf(L"CoSetProxyBlanket hr=0x%08X\n", static_cast<unsigned>(hr));

    if (argc >= 2 && _stricmp(argv[1], "enum") == 0) {
        for (int i = 2; i < argc; ++i) {
            wchar_t wcls[128];
            MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wcls, 128);
            EnumClass(svc, wcls);
        }
    } else if (argc >= 2 && _stricmp(argv[1], "getobj") == 0 && argc >= 3) {
        wchar_t wpath[256];
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, wpath, 256);
        GetObj(svc, wpath);
    } else {
        // 默认：ExecQuery 三连（回归对照）
        Query(svc, L"SELECT * FROM Win32_Processor", L"ProcessorId");
        Query(svc, L"SELECT * FROM Win32_BaseBoard", L"SerialNumber");
        Query(svc, L"SELECT * FROM Win32_DiskDrive WHERE MediaType = 'Fixed hard disk media'",
              L"SerialNumber");
    }

    svc->Release();
    CoUninitialize();
    return 0;
}
