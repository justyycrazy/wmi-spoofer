// probe-apartment.cpp —— 跨 apartment 探针：封送/直调/生命周期/跨进程，伪装是否存活
//
// 背景：wmi-spoofer.dll 的 IWbemServices 包装（CWbemServicesProxy）对未知 IID（含
// IMarshal）一律转发真实对象；回放枚举器（CReplayEnum）对 IMarshal 直接 E_NOINTERFACE。
// 本探针实证：把包装后的 services / 枚举器经 CoMarshalInterThreadInterfaceInStream
// 跨单元封送到另一线程后，读到的值是假是真、或封送本身失败（hr 是多少）。
//
// 用法：
//   probe-apartment.exe all        默认：按序跑情形 1-7（每情形独立线程，apartment 互不污染）
//   probe-apartment.exe only=N     只跑第 N 情形（1..7）
//   probe-apartment.exe xproc      情形 7 父进程（封送两个枚举器到临时文件并派生子进程）
//   probe-apartment.exe unmarshal <文件>  情形 7 子进程（读 OBJREF 文件尝试反封送并枚举）
//
// 情形表：
//   1 基线：单 STA 线程内 ExecQuery 读值（验证注入本身生效，一切"未见效"结论的前提）
//   2 同 MTA 双线程直传 services 指针（合法免封送，伪装应仍生效）
//   3 STA 创建 -> 封送 IID_IWbemServices -> MTA 线程 unmarshal -> ExecQuery 读值
//   4 STA 拿 ExecQuery 返回的枚举器 -> 封送 IID_IEnumWbemClassObject -> MTA 线程 unmarshal
//   5 STA 创建的 services 指针在 MTA 线程直传调用（不封送；COM 规则上违规但实践中
//     常见）——预期 RPC_E_WRONG_THREAD，与未注入时的原生行为一致（README 已知限制 ③）
//   6 封送后源线程先释放全部源引用并退出（B 再调用）——生命周期回归：早释放是否悬垂。
//     机制预期：FTM 直指针在 unmarshal 侧 QI/AddRef，B 持真实 COM 引用把对象钉住，
//     早释放安全；实测见输出。
//   7 跨进程封送对照（仅注入后有意义）：非规则类（原生 DCOM 代理枚举器）与规则类
//     （回放枚举器/FTM）各封送为 MSHCTX_LOCAL OBJREF 文件，由未注入的子进程
//     CoUnmarshalInterface——对照原生"正常工作"与回放枚举器"显式失败/崩溃"。
//
// 判定口径（对照注入前后各跑一次）：
//   读到假值 = 伪装存活；读到真值 = 静默失效；封送/unmarshal/查询返回失败 hr = 显式失败。
//   另对每个封送对象先做 QI(IID_IMarshal) 诊断，给出 QI 层的直接证据。
//
// 输出为 ASCII（任意代码页可跑）；读到的值原文打印，供注入前后人工对照。
//
// 构建：cl /O2 /EHsc /std:c++17 /utf-8 tools\probe-apartment.cpp /Fe:tools\probe-apartment.exe
//       /Fo:tools\ /link wbemuuid.lib ole32.lib oleaut32.lib
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ----------------------------------------------------------------------------
// 公共：COM 创建 / 查询输出
// ----------------------------------------------------------------------------

// 走 hook 点 1 的标准创建路径（CoCreateInstance(CLSID_WbemLocator) + ConnectServer）。
// 未注入时返回真实 services；注入后返回 CWbemServicesProxy 包装。
static HRESULT CreateServices(IWbemServices** out)
{
    *out = nullptr;
    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&loc));
    if (FAILED(hr) || !loc) {
        wprintf(L"    CoCreateInstance(WbemLocator) hr=0x%08X\n", static_cast<unsigned>(hr));
        return hr;
    }
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, out);
    SysFreeString(ns);
    wprintf(L"    ConnectServer(ROOT\\CIMV2) hr=0x%08X\n", static_cast<unsigned>(hr));
    loc->Release();
    return hr;
}

// 读单属性并打印（原值/假值原文，供注入前后对照）
static void PrintValue(IWbemClassObject* obj, const wchar_t* prop)
{
    VARIANT v;
    VariantInit(&v);
    HRESULT hr = obj->Get(prop, 0, &v, nullptr, nullptr);
    if (SUCCEEDED(hr) && v.vt == VT_BSTR && v.bstrVal)
        wprintf(L"      %s = %s\n", prop, v.bstrVal);
    else if (SUCCEEDED(hr))
        wprintf(L"      %s = (vt=%d)\n", prop, v.vt);
    else
        wprintf(L"      %s Get hr=0x%08X\n", prop, static_cast<unsigned>(hr));
    VariantClear(&v);
}

// 三条指纹查询（与 tools/wmitest.cpp 默认子命令一致，回归对照口径统一）
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
            PrintValue(obj, q.prop);
            obj->Release();
        }
        en->Release();
    }
}

// QI(IID_IMarshal) 诊断：封送前对对象直接查询，给出"COM 封送时会拿到谁的 marshaler"证据
static void QiMarshalDiag(IUnknown* unk, const wchar_t* tag)
{
    void* m = nullptr;
    HRESULT hr = unk->QueryInterface(IID_IMarshal, &m);
    wprintf(L"    QI(%s, IID_IMarshal) hr=0x%08X%s\n", tag, static_cast<unsigned>(hr),
            SUCCEEDED(hr) ? L" (forwarded to real marshaler?)" : L"");
    if (SUCCEEDED(hr))
        static_cast<IUnknown*>(m)->Release();
}

// ----------------------------------------------------------------------------
// 情形框架：每情形两个线程 + 两个事件（A 准备好 -> B 继续 -> 都结束）。
// 线程内各自 CoInitializeEx，主线程不初始化 COM，保证情形间 apartment 互不污染。
// ----------------------------------------------------------------------------

static HANDLE g_evtReady = nullptr; // A 侧就绪（指针/流已就绪，或失败也要置位让 B 收敛）
static HANDLE g_evtDone  = nullptr; // B 侧完成

static void RunCase(int n, const wchar_t* desc,
                    DWORD(WINAPI* fnA)(LPVOID),
                    DWORD(WINAPI* fnB)(LPVOID))
{
    wprintf(L"=== CASE %d: %s ===\n", n, desc);
    g_evtReady = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evtDone  = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_evtReady || !g_evtDone) {
        wprintf(L"    CreateEvent failed\n");
        if (g_evtReady) CloseHandle(g_evtReady);
        if (g_evtDone) CloseHandle(g_evtDone);
        g_evtReady = g_evtDone = nullptr;
        return;
    }
    HANDLE ha = CreateThread(nullptr, 0, fnA, nullptr, 0, nullptr);
    HANDLE hb = fnB ? CreateThread(nullptr, 0, fnB, nullptr, 0, nullptr) : nullptr;
    if (ha && (hb || !fnB)) {
        if (hb) {
            HANDLE hs[2] = { ha, hb };
            WaitForMultipleObjects(2, hs, TRUE, 120000);
        } else {
            WaitForSingleObject(ha, 120000); // 情形 1：只有 A 线程
        }
    } else {
        wprintf(L"    CreateThread failed (ha=%p hb=%p)\n", (void*)ha, (void*)hb);
    }
    if (ha) CloseHandle(ha);
    if (hb) CloseHandle(hb);
    CloseHandle(g_evtReady);
    CloseHandle(g_evtDone);
    g_evtReady = g_evtDone = nullptr;
    wprintf(L"=== CASE %d done ===\n", n);
}

// ----------------------------------------------------------------------------
// 情形 1：基线（单 STA 线程）
// ----------------------------------------------------------------------------

static DWORD WINAPI Case1Thread(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [STA] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        // 经典修复：不设 IMPERSONATE 时 Next 会 ACCESS_DENIED（与 wmitest 口径一致）。
        // 注入后该调用落在包装实现的 IClientSecurity 上，委托真实代理。
        HRESULT hb = CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                                       RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                                       nullptr, EOAC_DEFAULT);
        wprintf(L"    CoSetProxyBlanket hr=0x%08X\n", static_cast<unsigned>(hb));
        RunFingerprintQueries(svc);
        svc->Release();
    }
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 情形 2：同 MTA 双线程直传 services（合法免封送）
// ----------------------------------------------------------------------------

static IWbemServices* g_passSvc = nullptr; // 同 MTA 直传指针（两线程同属进程级 MTA）

static DWORD WINAPI Case2ThreadA(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-A] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtDone); // B 在等 done，收敛
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        g_passSvc = svc;
        wprintf(L"    [MTA-A] services created, pass pointer directly (same MTA)\n");
    }
    SetEvent(g_evtReady);            // 无论成败都放行 B
    if (WaitForSingleObject(g_evtDone, 60000) == WAIT_OBJECT_0 && g_passSvc)
        g_passSvc->Release();        // B 用完后再释放
    g_passSvc = nullptr;
    CoUninitialize();
    return 0;
}

static DWORD WINAPI Case2ThreadB(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-B] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtDone);
        return 1;
    }
    WaitForSingleObject(g_evtReady, 60000);
    if (g_passSvc) {
        // 合规消费者姿势：跨线程拿到代理先设 IMPERSONATE（否则 Next 必 ACCESS_DENIED，
        // 会污染"伪装真假"判定——基线实测已证实）
        HRESULT hb = CoSetProxyBlanket(g_passSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                       nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                       RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
        wprintf(L"    [MTA-B] CoSetProxyBlanket hr=0x%08X\n", static_cast<unsigned>(hb));
        wprintf(L"    [MTA-B] calling ExecQuery on passed pointer (no marshaling)\n");
        RunFingerprintQueries(g_passSvc);
    }
    SetEvent(g_evtDone);
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 情形 3：STA 创建 -> 封送 IWbemServices -> MTA 线程 unmarshal 后查询
// ----------------------------------------------------------------------------

static IStream* g_stream = nullptr; // 封送流（CoGetInterfaceAndReleaseStream 内部释放）

static DWORD WINAPI Case3ThreadA(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [STA-A] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtReady);
        SetEvent(g_evtDone);
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        QiMarshalDiag(svc, L"wrapped svc");
        HRESULT hm = CoMarshalInterThreadInterfaceInStream(IID_IWbemServices, svc, &g_stream);
        wprintf(L"    [STA-A] CoMarshalInterThreadInterfaceInStream hr=0x%08X\n",
                static_cast<unsigned>(hm));
        if (FAILED(hm))
            g_stream = nullptr;
    }
    SetEvent(g_evtReady);
    WaitForSingleObject(g_evtDone, 60000);
    if (svc) svc->Release();
    CoUninitialize();
    return 0;
}

static DWORD WINAPI Case3ThreadB(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-B] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtDone);
        return 1;
    }
    WaitForSingleObject(g_evtReady, 60000);
    if (g_stream) {
        IUnknown* unk = nullptr;
        HRESULT hu = CoGetInterfaceAndReleaseStream(g_stream, IID_IWbemServices,
                                                    reinterpret_cast<void**>(&unk));
        g_stream = nullptr; // 该函数总是释放流
        wprintf(L"    [MTA-B] CoGetInterfaceAndReleaseStream hr=0x%08X\n",
                static_cast<unsigned>(hu));
        if (SUCCEEDED(hu) && unk) {
            IWbemServices* svc2 = reinterpret_cast<IWbemServices*>(unk);
            // 合规消费者姿势：新 unmarshal 代理先设 IMPERSONATE 再查询
            HRESULT hb = CoSetProxyBlanket(svc2, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                           nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
            wprintf(L"    [MTA-B] CoSetProxyBlanket(unmarshaled svc) hr=0x%08X\n",
                    static_cast<unsigned>(hb));
            wprintf(L"    [MTA-B] unmarshaled, running ExecQuery on it\n");
            RunFingerprintQueries(svc2);
            unk->Release();
        }
    }
    SetEvent(g_evtDone);
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 情形 4：封送 ExecQuery 返回的（包装）枚举器
// ----------------------------------------------------------------------------

static DWORD WINAPI Case4ThreadA(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [STA-A] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtReady);
        SetEvent(g_evtDone);
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        // 与情形 1 口径对齐：先对 services 设 IMPERSONATE（WMI 枚举器调用与 services
        // 会话身份绑定——基线实测：只给枚举器设 blanket 时源线程 Next 也被拒 0x80041003）
        HRESULT hs = CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                       nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                       RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
        wprintf(L"    [STA-A] CoSetProxyBlanket(svc) hr=0x%08X\n", static_cast<unsigned>(hs));
        BSTR lang = SysAllocString(L"WQL");
        BSTR stmt = SysAllocString(L"SELECT * FROM Win32_BaseBoard");
        IEnumWbemClassObject* en = nullptr;
        HRESULT hq = svc->ExecQuery(lang, stmt, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
        SysFreeString(lang);
        SysFreeString(stmt);
        wprintf(L"    [STA-A] ExecQuery(BaseBoard) hr=0x%08X enum=%p\n",
                static_cast<unsigned>(hq), (void*)en);
        if (SUCCEEDED(hq) && en) {
            // 源线程先给枚举器设 IMPERSONATE（未注入=真实代理成功；注入后=包装的
            // no-op IClientSecurity 返回 S_OK），保证封送链路对照干净
            HRESULT hbl = CoSetProxyBlanket(en, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                            nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
            wprintf(L"    [STA-A] CoSetProxyBlanket(enum) hr=0x%08X\n",
                    static_cast<unsigned>(hbl));
            // 对照诊断：Clone 一份在源线程 Next，证明"枚举器本体在创建它的单元可用"，
            // 从而把跨单元 Next 的失败归因到封送/单元，而非探针或 WMI 服务本身
            IEnumWbemClassObject* en2 = nullptr;
            HRESULT hc = en->Clone(&en2);
            wprintf(L"    [STA-A] Clone(enum) hr=0x%08X\n", static_cast<unsigned>(hc));
            if (SUCCEEDED(hc) && en2) {
                IWbemClassObject* obj0 = nullptr;
                ULONG ret0 = 0;
                HRESULT hn0 = en2->Next(5000, 1, &obj0, &ret0);
                wprintf(L"    [STA-A] source-thread Next on clone hr=0x%08X ret=%u\n",
                        static_cast<unsigned>(hn0), ret0);
                if (hn0 == WBEM_S_NO_ERROR && obj0) {
                    PrintValue(obj0, L"SerialNumber");
                    obj0->Release();
                }
                en2->Release();
            }
            QiMarshalDiag(en, L"returned enum");
            HRESULT hm = CoMarshalInterThreadInterfaceInStream(
                IID_IEnumWbemClassObject, en, &g_stream);
            wprintf(L"    [STA-A] CoMarshalInterThreadInterfaceInStream(enum) hr=0x%08X\n",
                    static_cast<unsigned>(hm));
            if (FAILED(hm))
                g_stream = nullptr;
            en->Release();
        }
        svc->Release();
    }
    SetEvent(g_evtReady);
    WaitForSingleObject(g_evtDone, 60000);
    CoUninitialize();
    return 0;
}

static DWORD WINAPI Case4ThreadB(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-B] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtDone);
        return 1;
    }
    WaitForSingleObject(g_evtReady, 60000);
    if (g_stream) {
        IUnknown* unk = nullptr;
        HRESULT hu = CoGetInterfaceAndReleaseStream(g_stream, IID_IEnumWbemClassObject,
                                                    reinterpret_cast<void**>(&unk));
        g_stream = nullptr;
        wprintf(L"    [MTA-B] CoGetInterfaceAndReleaseStream(enum) hr=0x%08X\n",
                static_cast<unsigned>(hu));
        if (SUCCEEDED(hu) && unk) {
            IEnumWbemClassObject* en = reinterpret_cast<IEnumWbemClassObject*>(unk);
            // 诊断：读回设置前后的安全毯状态（确认 CoSetProxyBlanket 是否真的落在
            // unmarshal 代理上——真实代理上应生效；包装 no-op 实现上"成功但无效果"）
            DWORD a1 = 0, a2 = 0, l1 = 0, l2 = 0, c0 = 0;
            OLECHAR* pr = nullptr;
            HRESULT hq0 = CoQueryProxyBlanket(en, &a1, &a2, &pr, &l1, &l2, nullptr, &c0);
            wprintf(L"    [MTA-B] QueryBlanket(before) hr=0x%08X impLvl=%lu caps=0x%08lX\n",
                    static_cast<unsigned>(hq0), l2, c0);
            if (pr) CoTaskMemFree(pr);
            // 合规消费者姿势：新 unmarshal 的枚举器代理先设 IMPERSONATE 再 Next
            HRESULT hbl = CoSetProxyBlanket(en, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                            nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
            wprintf(L"    [MTA-B] CoSetProxyBlanket(unmarshaled enum) hr=0x%08X\n",
                    static_cast<unsigned>(hbl));
            OLECHAR* pr2 = nullptr;
            HRESULT hq1 = CoQueryProxyBlanket(en, &a1, &a2, &pr2, &l1, &l2, nullptr, &c0);
            wprintf(L"    [MTA-B] QueryBlanket(after) hr=0x%08X impLvl=%lu caps=0x%08lX\n",
                    static_cast<unsigned>(hq1), l2, c0);
            if (pr2) CoTaskMemFree(pr2);
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            HRESULT hn = en->Next(5000, 1, &obj, &ret);
            wprintf(L"    [MTA-B] Next hr=0x%08X ret=%u\n",
                    static_cast<unsigned>(hn), ret);
            if (hn == WBEM_S_NO_ERROR && obj) {
                PrintValue(obj, L"SerialNumber");
                obj->Release();
            }
            en->Release();
        }
    }
    SetEvent(g_evtDone);
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 情形 5：STA 创建 -> MTA 线程直传指针调用（不封送；现实中常见的违规直传模式）
// ----------------------------------------------------------------------------

static IWbemServices* g_passSvc5 = nullptr;

static DWORD WINAPI Case5ThreadA(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [STA-A] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtReady);
        SetEvent(g_evtDone);
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc)
        g_passSvc5 = svc; // 直传：不封送（COM 规则上违规，正是实践中容易出现的形态）
    SetEvent(g_evtReady);
    WaitForSingleObject(g_evtDone, 60000);
    if (g_passSvc5) g_passSvc5->Release();
    g_passSvc5 = nullptr;
    CoUninitialize();
    return 0;
}

static DWORD WINAPI Case5ThreadB(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-B] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtDone);
        return 1;
    }
    WaitForSingleObject(g_evtReady, 60000);
    if (g_passSvc5) {
        wprintf(L"    [MTA-B] direct call on STA-created pointer (NO marshaling)\n");
        HRESULT hb = CoSetProxyBlanket(g_passSvc5, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                       nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                       RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
        wprintf(L"    [MTA-B] CoSetProxyBlanket hr=0x%08X\n", static_cast<unsigned>(hb));
        RunFingerprintQueries(g_passSvc5);
    }
    SetEvent(g_evtDone);
    CoUninitialize();
    return 0;
}

// ----------------------------------------------------------------------------
// 情形 6：封送后源线程先释放全部源引用并退出，B 单元再调用（生命周期回归测试）
// ----------------------------------------------------------------------------

static IStream* g_stream6     = nullptr;
static HANDLE   g_evt6Unmarsh = nullptr; // B 完成 unmarshal
static HANDLE   g_evt6Rel     = nullptr; // A 已释放全部源引用
static HANDLE   g_evt6Done    = nullptr; // B 完成
static IUnknown* g_enum6      = nullptr; // B 侧 unmarshal 出的枚举器

static DWORD WINAPI Case6ThreadA(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [STA-A] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evtReady); SetEvent(g_evt6Unmarsh); SetEvent(g_evt6Rel);
        SetEvent(g_evt6Done);
        return 1;
    }
    IWbemServices* svc = nullptr;
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                          RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_DEFAULT);
        BSTR lang = SysAllocString(L"WQL");
        BSTR stmt = SysAllocString(L"SELECT * FROM Win32_BaseBoard");
        IEnumWbemClassObject* en = nullptr;
        HRESULT hq = svc->ExecQuery(lang, stmt, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
        SysFreeString(lang);
        SysFreeString(stmt);
        wprintf(L"    [STA-A] ExecQuery(BaseBoard) hr=0x%08X\n", static_cast<unsigned>(hq));
        if (SUCCEEDED(hq) && en) {
            CoSetProxyBlanket(en, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_DEFAULT);
            QiMarshalDiag(en, L"replay enum");
            HRESULT hm = CoMarshalInterThreadInterfaceInStream(
                IID_IEnumWbemClassObject, en, &g_stream6);
            wprintf(L"    [STA-A] marshal(enum) hr=0x%08X\n", static_cast<unsigned>(hm));
            if (FAILED(hm))
                g_stream6 = nullptr;
            if (en) en->Release(); // A 自己的消费引用立即交给流（源仅剩封送语义）
        }
        svc->Release();
    }
    SetEvent(g_evtReady);
    // 等 B unmarshal 完成后，释放 A 侧剩余引用并退出线程（连 STA apartment 一起撤）
    if (WaitForSingleObject(g_evt6Unmarsh, 60000) == WAIT_OBJECT_0)
        wprintf(L"    [STA-A] B unmarshaled; A releasing all source refs & exiting now\n");
    SetEvent(g_evt6Rel);
    CoUninitialize();
    return 0;
}

static DWORD WINAPI Case6ThreadB(LPVOID)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"    [MTA-B] CoInitializeEx hr=0x%08X\n", static_cast<unsigned>(hr));
        SetEvent(g_evt6Unmarsh); SetEvent(g_evt6Rel); SetEvent(g_evt6Done);
        return 1;
    }
    WaitForSingleObject(g_evtReady, 60000);
    if (g_stream6) {
        HRESULT hu = CoGetInterfaceAndReleaseStream(g_stream6, IID_IEnumWbemClassObject,
                                                    reinterpret_cast<void**>(&g_enum6));
        g_stream6 = nullptr;
        wprintf(L"    [MTA-B] unmarshal hr=0x%08X\n", static_cast<unsigned>(hu));
    }
    SetEvent(g_evt6Unmarsh);
    // 等 A 释放全部源引用并退出线程之后再调用——极限条件下验证生命周期
    WaitForSingleObject(g_evt6Rel, 60000);
    wprintf(L"    [MTA-B] source released & A thread gone; calling Next now\n");
    if (g_enum6) {
        IEnumWbemClassObject* en = reinterpret_cast<IEnumWbemClassObject*>(g_enum6);
        CoSetProxyBlanket(en, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                          RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_DEFAULT);
        ULONG count = 0;
        for (;;) {
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            HRESULT hn = en->Next(5000, 1, &obj, &ret);
            if (hn != WBEM_S_NO_ERROR || ret == 0 || !obj) {
                wprintf(L"    [MTA-B] Next end h=0x%08X ret=%u (total %u)\n",
                        static_cast<unsigned>(hn), ret, count);
                break;
            }
            ++count;
            PrintValue(obj, L"SerialNumber");
            obj->Release();
        }
        wprintf(L"    [MTA-B] RESULT: %s (enumerated %u)\n",
                count > 0 ? L"ALIVE - lifetime managed by shared refcount" : L"DEAD/EMPTY",
                count);
        g_enum6->Release();
        g_enum6 = nullptr;
    }
    SetEvent(g_evt6Done);
    CoUninitialize();
    return 0;
}

static void Case6Run(void)
{
    wprintf(L"=== CASE 6: marshal enum, source releases BEFORE B uses it (lifetime check) ===\n");
    g_evtReady     = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evt6Unmarsh  = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evt6Rel      = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evt6Done     = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_evtReady && g_evt6Unmarsh && g_evt6Rel && g_evt6Done) {
        HANDLE ha = CreateThread(nullptr, 0, Case6ThreadA, nullptr, 0, nullptr);
        HANDLE hb = CreateThread(nullptr, 0, Case6ThreadB, nullptr, 0, nullptr);
        if (ha && hb) {
            HANDLE hs[2] = { ha, hb };
            WaitForMultipleObjects(2, hs, TRUE, 120000);
        }
        if (ha) CloseHandle(ha);
        if (hb) CloseHandle(hb);
    }
    if (g_evtReady) CloseHandle(g_evtReady);
    if (g_evt6Unmarsh) CloseHandle(g_evt6Unmarsh);
    if (g_evt6Rel) CloseHandle(g_evt6Rel);
    if (g_evt6Done) CloseHandle(g_evt6Done);
    g_evtReady = g_evt6Unmarsh = g_evt6Rel = g_evt6Done = nullptr;
    wprintf(L"=== CASE 6 done ===\n");
}

// ----------------------------------------------------------------------------
// 情形 7：跨进程封送对照（原生代理枚举器 vs 回放枚举器/FTM）
// ----------------------------------------------------------------------------

static const wchar_t kFile7Native[] = L"wmi-spoofer-probe7-native.objref";
static const wchar_t kFile7Replay[] = L"wmi-spoofer-probe7-replay.objref";

static bool WriteStreamToFile(IStream* stm, const wchar_t* path, ULONG* outBytes)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    stm->Seek(zero, STREAM_SEEK_SET, nullptr);
    STATSTG st{};
    if (FAILED(stm->Stat(&st, STATFLAG_NONAME)) || st.cbSize.QuadPart <= 0)
        return false;
    const size_t n = static_cast<size_t>(st.cbSize.QuadPart);
    unsigned char* buf = new unsigned char[n];
    ULONG total = 0;
    while (total < n) {
        ULONG got = 0;
        if (FAILED(stm->Read(buf + total, static_cast<ULONG>(n - total), &got)) || got == 0)
            break;
        total += got;
    }
    bool ok = false;
    if (total == n) {
        HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            ok = WriteFile(h, buf, total, &w, nullptr) && w == total;
            CloseHandle(h);
        }
    }
    delete[] buf;
    if (outBytes) *outBytes = total;
    return ok;
}

// 把一个枚举器以 MSHCTX_LOCAL 封送进 OBJREF 文件（含 GetUnmarshalClass 诊断）
static void MarshalEnumToFile(IWbemServices* svc, const wchar_t* wql, const wchar_t* file)
{
    BSTR lang = SysAllocString(L"WQL");
    BSTR stmt = SysAllocString(wql);
    IEnumWbemClassObject* en = nullptr;
    HRESULT hq = svc->ExecQuery(lang, stmt, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    SysFreeString(lang);
    SysFreeString(stmt);
    wprintf(L"    [parent] ExecQuery hr=0x%08X [%s]\n", static_cast<unsigned>(hq), wql);
    if (FAILED(hq) || !en)
        return;
    // 诊断：该对象的 marshaler 对"跨进程"目的地给出的 unmarshal 类
    IMarshal* m = nullptr;
    if (SUCCEEDED(en->QueryInterface(IID_IMarshal, reinterpret_cast<void**>(&m)))) {
        CLSID cid{};
        if (SUCCEEDED(m->GetUnmarshalClass(IID_IEnumWbemClassObject, en, MSHCTX_LOCAL,
                                           nullptr, MSHLFLAGS_NORMAL, &cid))) {
            LPOLESTR s = nullptr;
            if (SUCCEEDED(StringFromCLSID(cid, &s))) {
                wprintf(L"    [parent] GetUnmarshalClass(MSHCTX_LOCAL) -> %s\n", s);
                CoTaskMemFree(s);
            }
        }
        m->Release();
    }
    ULONG max = 0;
    HRESULT hsz = CoGetMarshalSizeMax(&max, IID_IEnumWbemClassObject, en, MSHCTX_LOCAL,
                                      nullptr, MSHLFLAGS_NORMAL);
    IStream* stm = nullptr;
    HRESULT hm = (SUCCEEDED(hsz)) ? CreateStreamOnHGlobal(nullptr, TRUE, &stm) : hsz;
    if (SUCCEEDED(hm) && stm) {
        hm = CoMarshalInterface(stm, IID_IEnumWbemClassObject, en, MSHCTX_LOCAL, nullptr,
                                MSHLFLAGS_NORMAL);
        wprintf(L"    [parent] CoMarshalInterface(MSHCTX_LOCAL) hr=0x%08X\n",
                static_cast<unsigned>(hm));
        if (SUCCEEDED(hm)) {
            ULONG wrote = 0;
            if (WriteStreamToFile(stm, file, &wrote))
                wprintf(L"    [parent] objref written: %s (%lu bytes)\n", file, wrote);
            else
                wprintf(L"    [parent] write file failed: %s\n", file);
        }
        stm->Release();
    } else {
        wprintf(L"    [parent] marshal setup failed hr=0x%08X\n", static_cast<unsigned>(hm));
    }
    en->Release();
}

// 父进程：封送两个枚举器（非规则类=原生代理；规则类=回放枚举器）并派生子进程反封送
static DWORD RunXprocParent(void)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return 1;
    wprintf(L"=== CASE 7: cross-process marshal (native vs replay/FTM enum) ===\n");
    IWbemServices* svc = nullptr;
    wchar_t dir[MAX_PATH] = { 0 };
    wchar_t nativePath[MAX_PATH * 2] = { 0 };
    wchar_t replayPath[MAX_PATH * 2] = { 0 };
    wchar_t self[MAX_PATH] = { 0 };
    if (SUCCEEDED(CreateServices(&svc)) && svc) {
        CoSetProxyBlanket(svc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                          RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_DEFAULT);
        GetTempPathW(MAX_PATH, dir);
        swprintf(nativePath, MAX_PATH * 2, L"%s%s", dir, kFile7Native);
        swprintf(replayPath, MAX_PATH * 2, L"%s%s", dir, kFile7Replay);
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        // 非规则类：ExecQuery 原样转发 -> 原生 DCOM 代理枚举器（跨进程封送的对照组）
        MarshalEnumToFile(svc, L"SELECT * FROM Win32_ComputerSystem", nativePath);
        // 规则类：命中规则 -> 回放枚举器（FTM 直指针）
        MarshalEnumToFile(svc, L"SELECT * FROM Win32_Processor", replayPath);
        svc->Release();
    }
    // 逐个派生子进程反封送（父进程注入时 CHILDREN 缺省 0，子进程不受注入传播）
    const wchar_t* tags[2]  = { L"native", L"replay(FTM)" };
    const wchar_t* files[2] = { nativePath, replayPath };
    for (int i = 0; i < 2; ++i) {
        wchar_t cmd[1024];
        swprintf(cmd, 1024, L"\"%s\" unmarshal \"%s\"", self, files[i]);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        wprintf(L"    [parent] spawning child to unmarshal %s ...\n", tags[i]);
        if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                           &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 30000);
            DWORD code = 0;
            GetExitCodeProcess(pi.hProcess, &code);
            wprintf(L"    [parent] child(%s) exit code = 0x%08lX%s\n", tags[i], code,
                    code == 0 ? L" (OK)"
                              : (code == STILL_ACTIVE ? L" (still active!)" : L""));
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            wprintf(L"    [parent] CreateProcessW failed %lu\n", GetLastError());
        }
    }
    wprintf(L"=== CASE 7 done ===\n");
    CoUninitialize();
    return 0;
}

// 子进程：读 OBJREF 文件 -> CoUnmarshalInterface -> 设 blanket -> 枚举
static int RunUnmarshalChild(const wchar_t* path)
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return 1;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"    [child] open objref failed: %s\n", path);
        CoUninitialize();
        return 1;
    }
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 0x4000000) {
        wprintf(L"    [child] bad objref size\n");
        CloseHandle(h);
        CoUninitialize();
        return 1;
    }
    const size_t n = static_cast<size_t>(sz.QuadPart);
    unsigned char* buf = new unsigned char[n];
    DWORD got = 0;
    const BOOL okr = ReadFile(h, buf, static_cast<DWORD>(n), &got, nullptr);
    CloseHandle(h);
    if (!okr || got != n) {
        wprintf(L"    [child] read objref failed\n");
        delete[] buf;
        CoUninitialize();
        return 1;
    }
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, n);
    IStream* stm = nullptr;
    IUnknown* unk = nullptr;
    HRESULT hm = E_FAIL;
    if (hg) {
        void* p = GlobalLock(hg);
        if (p) {
            memcpy(p, buf, n);
            GlobalUnlock(hg);
        }
        hm = CreateStreamOnHGlobal(hg, FALSE, &stm);
        wprintf(L"    [child] stream ready (%zu bytes)\n", n);
    }
    if (SUCCEEDED(hm) && stm) {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        stm->Seek(zero, STREAM_SEEK_SET, nullptr);
        hm = CoUnmarshalInterface(stm, IID_IEnumWbemClassObject,
                                  reinterpret_cast<void**>(&unk));
        wprintf(L"    [child] CoUnmarshalInterface hr=0x%08X\n", static_cast<unsigned>(hm));
    } else {
        wprintf(L"    [child] stream setup failed\n");
    }
    int rc = 1;
    if (SUCCEEDED(hm) && unk) {
        IEnumWbemClassObject* en = reinterpret_cast<IEnumWbemClassObject*>(unk);
        CoSetProxyBlanket(en, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, nullptr,
                          RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_DEFAULT);
        ULONG count = 0;
        for (;;) {
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            HRESULT hn = en->Next(5000, 1, &obj, &ret);
            if (hn != WBEM_S_NO_ERROR || ret == 0 || !obj) {
                wprintf(L"    [child] Next end h=0x%08X ret=%u (total %u)\n",
                        static_cast<unsigned>(hn), ret, count);
                break;
            }
            ++count;
            PrintValue(obj, L"__CLASS");
            PrintValue(obj, L"SerialNumber");
            PrintValue(obj, L"ProcessorId");
            obj->Release();
        }
        wprintf(L"    [child] RESULT: OK (enumerated %u)\n", count);
        rc = 0;
        unk->Release();
    } else {
        wprintf(L"    [child] RESULT: FAIL hr=0x%08X\n", static_cast<unsigned>(hm));
    }
    if (stm) stm->Release();
    if (hg) GlobalFree(hg);
    delete[] buf;
    CoUninitialize();
    return rc;
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // 情形 7 的子进程入口：读 OBJREF 文件尝试跨进程反封送（退出码 0=OK，1=失败）
    if (argc >= 3 && _stricmp(argv[1], "unmarshal") == 0) {
        wchar_t wpath[MAX_PATH * 2] = { 0 };
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, wpath, MAX_PATH * 2);
        return RunUnmarshalChild(wpath);
    }
    // 情形 7 的父进程入口：封送两个枚举器并派生子进程对照
    if (argc >= 2 && _stricmp(argv[1], "xproc") == 0)
        return RunXprocParent();

    int only = 0;
    if (argc >= 2 && _strnicmp(argv[1], "only=", 5) == 0)
        only = atoi(argv[1] + 5);
    const bool runAll = (only == 0);

    if (runAll || only == 1)
        RunCase(1, L"baseline: single STA thread, ExecQuery reads (injection precheck)",
                Case1Thread, nullptr);
    if (runAll || only == 2)
        RunCase(2, L"same-MTA direct pointer pass (no marshaling, spoof should survive)",
                Case2ThreadA, Case2ThreadB);
    if (runAll || only == 3)
        RunCase(3, L"STA -> marshal IWbemServices -> MTA thread unmarshals and queries",
                Case3ThreadA, Case3ThreadB);
    if (runAll || only == 4)
        RunCase(4, L"marshal returned (wrapped) IEnumWbemClassObject -> MTA thread",
                Case4ThreadA, Case4ThreadB);
    if (runAll || only == 5)
        RunCase(5, L"STA-created pointer used directly on MTA thread (NO marshaling)",
                Case5ThreadA, Case5ThreadB);
    if (runAll || only == 6)
        Case6Run();
    if (runAll || only == 7)
        RunXprocParent();
    return 0;
}
