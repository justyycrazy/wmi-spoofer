// ============================================================================
//  test_pure.cpp —— 纯逻辑单元测试
//  （parse.cpp / config.cpp / log.cpp + 头文件实现 replay_enum.h / proxies.h）
//
//  构建+运行：tests\build_tests.bat（需 x64 Native Tools 环境）
//  退出码：0 = 全部通过；非 0 = 失败数
// ============================================================================

#include <windows.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <wbemcli.h>

#include <atomic>
#include <cwchar>
#include <new>
#include <thread>
#include <vector>

#include "common.h"
#include "config.h"
#include "log.h"
#include "parse.h"
#include "proxies.h"
#include "replay_enum.h"

static int g_failed = 0;
static int g_total  = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_total;                                                             \
        if (!(cond)) {                                                         \
            wprintf(L"FAIL(#%d): %hs\n", g_total, #cond);                      \
            ++g_failed;                                                        \
        }                                                                      \
    } while (0)

// ----------------------------------------------------------------------------
// TrimW / ToLower / MaskValue
// ----------------------------------------------------------------------------

static void TestStringHelpers()
{
    CHECK(TrimW(L"  a b  ") == L"a b");
    CHECK(TrimW(L"\t\r\n") == L"");
    CHECK(TrimW(L"abc") == L"abc");

    CHECK(ToLower(L"AbC") == L"abc");
    CHECK(ToLower(L"WIN32_BaseBoard") == L"win32_baseboard");
}

static void TestMaskValue()
{
    // 短值（<=4）只记长度
    CHECK(MaskValue(L"") == L"<长度0>");
    CHECK(MaskValue(L"AB") == L"<长度2>");
    CHECK(MaskValue(L"ABCD") == L"<长度4>");
    // 长值：首2…末2<长度N>
    CHECK(MaskValue(L"ABCDEF") == L"AB…EF<长度6>");
    CHECK(MaskValue(L"SMOKETEST-999") == L"SM…99<长度13>");
}

// ----------------------------------------------------------------------------
// GetEnvValue / EnvFlag（环境变量四态）
// ----------------------------------------------------------------------------

static void TestEnv()
{
    // GetEnvValue：缺失 -> false；空白值 -> false；正常值去两端空白
    SetEnvironmentVariableW(L"WMI_TEST_A", nullptr);
    std::wstring out = L"sentinel";
    CHECK(GetEnvValue(L"WMI_TEST_A", out) == false);
    CHECK(out == L"sentinel"); // 不覆盖 out
    SetEnvironmentVariableW(L"WMI_TEST_A", L"   ");
    CHECK(GetEnvValue(L"WMI_TEST_A", out) == false);
    SetEnvironmentVariableW(L"WMI_TEST_A", L"  x y  ");
    CHECK(GetEnvValue(L"WMI_TEST_A", out) == true);
    CHECK(out == L"x y");
    SetEnvironmentVariableW(L"WMI_TEST_A", nullptr);

    // EnvFlag：缺失用默认；"0"/false 关（大小写不敏感）；其余开
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", nullptr);
    CHECK(EnvFlag(L"WMI_TEST_FLAG", true) == true);
    CHECK(EnvFlag(L"WMI_TEST_FLAG", false) == false);
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", L"0");
    CHECK(EnvFlag(L"WMI_TEST_FLAG", true) == false);
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", L"FaLsE");
    CHECK(EnvFlag(L"WMI_TEST_FLAG", true) == false);
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", L"1");
    CHECK(EnvFlag(L"WMI_TEST_FLAG", false) == true);
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", L"anything");
    CHECK(EnvFlag(L"WMI_TEST_FLAG", false) == true);
    SetEnvironmentVariableW(L"WMI_TEST_FLAG", nullptr);
}

// ----------------------------------------------------------------------------
// EmptyTokenToClass
// ----------------------------------------------------------------------------

static void TestEmptyToken()
{
    // 混合大小写输入：验证函数自身的大小写不敏感（2026-11 修复：原实现不做
    // 大小写归一，注释却声称“大小写不敏感”，大写输入会返回 nullptr）
    CHECK(wcscmp(EmptyTokenToClass(L"board"), L"Win32_BaseBoard") == 0);
    CHECK(wcscmp(EmptyTokenToClass(L"BASEBOARD"), L"Win32_BaseBoard") == 0);
    CHECK(wcscmp(EmptyTokenToClass(L"cpu"), L"Win32_Processor") == 0);
    CHECK(wcscmp(EmptyTokenToClass(L"Processor"), L"Win32_Processor") == 0);
    CHECK(wcscmp(EmptyTokenToClass(L"disk"), L"Win32_DiskDrive") == 0);
    CHECK(wcscmp(EmptyTokenToClass(L"DISKDRIVE"), L"Win32_DiskDrive") == 0);
    CHECK(EmptyTokenToClass(L"unknown") == nullptr);
    CHECK(EmptyTokenToClass(L"") == nullptr);
}

// ----------------------------------------------------------------------------
// LoadConfig 端到端（环境变量 -> g_rules）
// ----------------------------------------------------------------------------

static void ClearSpoofEnvs()
{
    SetEnvironmentVariableW(L"WMI_SPOOFER_BOARD", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_CPU", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_DISK", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_EMPTY", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_CHILDREN", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_LOG", nullptr);
}

static void TestLoadConfig()
{
    // 测试进程内 g_logPath 为空（未走 BuildPaths），LoadConfig 内的 Log 全部静默
    ClearSpoofEnvs();

    // 场景 A：无任何变量 -> 空规则表 + 默认开关
    LoadConfig();
    CHECK(g_rules.empty());
    CHECK(g_injectChildren == true);
    CHECK(g_logEnabled == true);

    // 场景 B：EMPTY=board + BOARD 假值 -> BaseBoard denyAll（假值被忽略），无其他规则
    SetEnvironmentVariableW(L"WMI_SPOOFER_EMPTY", L"board");
    SetEnvironmentVariableW(L"WMI_SPOOFER_BOARD", L"FAKE-12");
    LoadConfig();
    CHECK(g_rules.size() == 1);
    CHECK(g_rules.count(L"win32_baseboard") == 1);
    CHECK(g_rules[L"win32_baseboard"].denyAll == true);
    CHECK(g_rules[L"win32_baseboard"].props.empty());

    // 场景 C：伪值模式 BOARD/CPU -> 两条 props 规则
    SetEnvironmentVariableW(L"WMI_SPOOFER_EMPTY", nullptr);
    SetEnvironmentVariableW(L"WMI_SPOOFER_CPU", L"CAFEBABE00000456");
    LoadConfig();
    CHECK(g_rules.size() == 2);
    CHECK(g_rules.count(L"win32_baseboard") == 1);
    CHECK(g_rules.count(L"win32_processor") == 1);
    CHECK(g_rules[L"win32_baseboard"].props.size() == 1);
    CHECK(g_rules[L"win32_baseboard"].props[0].name == L"SerialNumber");
    CHECK(g_rules[L"win32_baseboard"].props[0].value == L"FAKE-12");
    CHECK(g_rules[L"win32_processor"].props[0].value == L"CAFEBABE00000456");

    // 场景 D：CHILDREN=0 / LOG=0 开关
    SetEnvironmentVariableW(L"WMI_SPOOFER_CHILDREN", L"0");
    SetEnvironmentVariableW(L"WMI_SPOOFER_LOG", L"0");
    LoadConfig();
    CHECK(g_injectChildren == false);
    CHECK(g_logEnabled == false);

    ClearSpoofEnvs();
    LoadConfig(); // 复位为默认（空规则 + 开关全开）
    CHECK(g_rules.empty());
    CHECK(g_injectChildren == true);
    CHECK(g_logEnabled == true);
}

// ----------------------------------------------------------------------------
// ParseQueryClass / ParseObjectPathClass / VariantToString
// ----------------------------------------------------------------------------

static void TestParse()
{
    CHECK(ParseQueryClass(L"SELECT * FROM Win32_BaseBoard") == L"win32_baseboard");
    CHECK(ParseQueryClass(L"select * from win32_processor") == L"win32_processor");
    CHECK(ParseQueryClass(L"") == L"");
    CHECK(ParseQueryClass(L"just garbage") == L"");

    bool inst = true;
    CHECK(ParseObjectPathClass(L"Win32_BaseBoard", &inst) == L"win32_baseboard");
    CHECK(inst == false); // 类定义：放行真实数据

    CHECK(ParseObjectPathClass(L"Win32_BaseBoard=@", &inst) == L"win32_baseboard");
    CHECK(inst == true);

    CHECK(ParseObjectPathClass(L"Win32_Processor.DeviceID=\"CPU0\"", &inst) ==
          L"win32_processor");
    CHECK(inst == true);

    CHECK(ParseObjectPathClass(L"root\\cimv2:Win32_BaseBoard=@", &inst) ==
          L"win32_baseboard");
    CHECK(inst == true);

    // 已知限制：键值含冒号 -> 类名被切在冒号后（fail-safe：不命中规则表即放行）
    CHECK(ParseObjectPathClass(L"Win32_LogicalDisk.DeviceID=\"C:\"", &inst) == L"\"");
    CHECK(inst == false);

    CHECK(ParseObjectPathClass(L"", &inst) == L"");
}

static void TestVariantToString()
{
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_EMPTY;
    CHECK(VariantToString(v) == L"<EMPTY>");
    v.vt = VT_NULL;
    CHECK(VariantToString(v) == L"<NULL>");

    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(L"hello");
    CHECK(VariantToString(v) == L"hello");
    VariantClear(&v);

    v.vt = VT_I4;
    v.lVal = 42;
    CHECK(VariantToString(v) == L"42");
    VariantClear(&v);
}

// ----------------------------------------------------------------------------
// CReplayEnum（replay_enum.h，链接自本 exe）
// ----------------------------------------------------------------------------

// 最小 fake：CReplayEnum 只对缓存对象调 AddRef/Release，其余接口无人调用。
// Release 不 delete（栈上对象，进程退出即回收）。
class FakeWbemObject : public IWbemClassObject
{
    volatile LONG m_ref;

public:
    int id = -1; // 并发压力测试用：按 id 统计每个“位置”被消费的次数

    FakeWbemObject() : m_ref(1) {}
    explicit FakeWbemObject(int i) : m_ref(1), id(i) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown) {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        return static_cast<ULONG>(InterlockedDecrement(&m_ref)); // 栈对象不 delete
    }

    HRESULT STDMETHODCALLTYPE GetQualifierSet(IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Get(LPCWSTR, long, VARIANT*, CIMTYPE*, long*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Put(LPCWSTR, long, VARIANT*, CIMTYPE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Delete(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNames(LPCWSTR, long, VARIANT*, SAFEARRAY**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE BeginEnumeration(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Next(long, BSTR*, VARIANT*, CIMTYPE*, long*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EndEnumeration() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyQualifierSet(LPCWSTR, IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Clone(IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetObjectText(long, BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SpawnDerivedClass(long, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SpawnInstance(long, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CompareTo(long, IWbemClassObject*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyOrigin(LPCWSTR, BSTR*) override { return E_NOTIMPL; }
    // ---- 此 SDK 头的扩展方法段（签名照抄 wbemcli.h；测试无人调用）----
    HRESULT STDMETHODCALLTYPE InheritsFrom(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethod(LPCWSTR, long, IWbemClassObject**, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE PutMethod(LPCWSTR, long, IWbemClassObject*, IWbemClassObject*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeleteMethod(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE BeginMethodEnumeration(long) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE NextMethod(long, BSTR*, IWbemClassObject**, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EndMethodEnumeration() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethodQualifierSet(LPCWSTR, IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethodOrigin(LPCWSTR, BSTR*) override { return E_NOTIMPL; }
};

// R2 回归断言：Clone/CopyProxy 必须保留当前枚举位置（修复前从头重放）。
// 三个 fake 对象 A/B/C：消费 1 个后克隆，克隆的 Next 应返回第 2 个而非第 1 个。
static void TestReplayEnum()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); // FTM 聚合需要 COM
    CHECK(SUCCEEDED(hr));
    if (FAILED(hr))
        return;

    FakeWbemObject a, b, c;
    IWbemClassObject* pa = &a;
    IWbemClassObject* pb = &b;
    IWbemClassObject* pc = &c;
    std::vector<IWbemClassObject*> items = { pa, pb, pc };
    CReplayEnum e(std::move(items));

    IWbemClassObject* obj = nullptr;
    ULONG ret = 0;
    CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == pa);
    if (obj) { obj->Release(); obj = nullptr; }

    IEnumWbemClassObject* clone = nullptr;
    CHECK(e.Clone(&clone) == WBEM_S_NO_ERROR && clone != nullptr);
    CHECK(clone->Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == pb);
    if (obj) { obj->Release(); obj = nullptr; }

    // 原枚举器继续推进不受克隆影响：下一个仍是 pb，耗尽后 S_FALSE
    CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == pb);
    if (obj) { obj->Release(); obj = nullptr; }
    CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == pc);
    if (obj) { obj->Release(); obj = nullptr; }
    CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_FALSE && ret == 0);
    if (obj) { obj->Release(); obj = nullptr; }

    // CopyProxy 同语义（IClientSecurity 上的复制，而非重放整个枚举）：
    // 此时代码已耗尽（3/3），代理克隆应保留“已耗尽”位置 -> Next 返回 S_FALSE
    IUnknown* proxy = nullptr;
    CHECK(e.CopyProxy(nullptr, &proxy) == WBEM_S_NO_ERROR && proxy != nullptr);
    IEnumWbemClassObject* pen = nullptr;
    CHECK(proxy->QueryInterface(IID_IEnumWbemClassObject,
                                reinterpret_cast<void**>(&pen)) == WBEM_S_NO_ERROR);
    CHECK(pen->Next(5000, 1, &obj, &ret) == WBEM_S_FALSE && ret == 0);
    if (obj) { obj->Release(); obj = nullptr; }
    if (pen) pen->Release();
    if (proxy) proxy->Release();
    if (clone) clone->Release();

    CoUninitialize();
}

// ----------------------------------------------------------------------------
// Skip 合约——恰好跳完（nCount == remain）是合法操作返回 S_OK，
// 越过末尾（nCount > remain）才返回 WBEM_S_FALSE
// ----------------------------------------------------------------------------

static void TestReplayEnumSkip()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CHECK(SUCCEEDED(hr));
    if (FAILED(hr))
        return;

    FakeWbemObject a, b, c;
    {
        std::vector<IWbemClassObject*> items = { &a, &b, &c };
        CReplayEnum e(std::move(items));
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && obj == &a);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(e.Skip(5000, 2) == WBEM_S_NO_ERROR); // 恰好跳完剩余 2 个（==）：S_OK（修复点）
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_FALSE && ret == 0);
    }
    {
        std::vector<IWbemClassObject*> items = { &a, &b, &c };
        CReplayEnum e(std::move(items));
        CHECK(e.Skip(5000, 3) == WBEM_S_NO_ERROR); // 恰好跳完全部（==）：S_OK
        CHECK(e.Skip(5000, 1) == WBEM_S_FALSE);    // 已耗尽后再跳：越过
    }
    {
        std::vector<IWbemClassObject*> items = { &a, &b, &c };
        CReplayEnum e(std::move(items));
        CHECK(e.Skip(5000, 4) == WBEM_S_FALSE); // 越过末尾（>）：S_FALSE
    }
    {
        std::vector<IWbemClassObject*> items = {};
        CReplayEnum e(std::move(items)); // 空枚举
        CHECK(e.Skip(5000, 0) == WBEM_S_NO_ERROR); // Skip(0) 不算越过
        CHECK(e.Skip(5000, 1) == WBEM_S_FALSE);
    }
    CoUninitialize();
}

// ----------------------------------------------------------------------------
// 抽干阶段的原始终止错误必须透传给调用方（此前被吞成正常结束）。
// 语义（本轮修正）：缓存内对象先正常交付（含批量部分交付，返回 WBEM_S_FALSE）；
// 缓存耗尽后才幂等透传原始终止 HRESULT。批量请求不得挡住已缓存的未交付对象
// （旧实现 hitFailPoint 挡住缓存是缺陷，旧测试把该行为固化成了预期）。
// 克隆保留枚举位置与终止状态。
// ----------------------------------------------------------------------------

static void TestReplayEnumTerminalHr()
{
    FakeWbemObject a, b;
    IWbemClassObject* obj = nullptr;
    ULONG ret = 0;

    // 场景 1：逐个取回缓存后，耗尽点透传终止错误且幂等；uCount=0 保持 S_OK + 0
    {
        std::vector<IWbemClassObject*> items = { &a, &b };
        CReplayEnum e(std::move(items), 0, E_ACCESSDENIED); // 模拟第 3 次 Next 失败

        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == &a);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && ret == 1 && obj == &b);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(e.Next(5000, 1, &obj, &ret) == E_ACCESSDENIED && ret == 0); // 耗尽透传
        CHECK(e.Next(5000, 1, &obj, &ret) == E_ACCESSDENIED && ret == 0); // 幂等
        CHECK(e.Next(5000, 0, &obj, &ret) == WBEM_S_NO_ERROR && ret == 0); // uCount=0
    }

    // 场景 2：从初始位置直接批量请求 uCount > 缓存剩余 ——
    // 先交付全部缓存对象（WBEM_S_FALSE + ret=2），下一次调用才透传终止错误
    {
        std::vector<IWbemClassObject*> items = { &a, &b };
        CReplayEnum e(std::move(items), 0, E_ACCESSDENIED);

        IWbemClassObject* got[5] = {};
        ULONG gotN = 0;
        CHECK(e.Next(5000, 5, got, &gotN) == WBEM_S_FALSE && gotN == 2);
        CHECK(got[0] == &a && got[1] == &b);
        for (ULONG i = 0; i < gotN; ++i)
            got[i]->Release();
        CHECK(e.Next(5000, 5, got, &gotN) == E_ACCESSDENIED && gotN == 0); // 已耗尽
        CHECK(e.Next(5000, 5, got, &gotN) == E_ACCESSDENIED && gotN == 0); // 幂等
    }

    // 场景 3：干净结束（endHr 默认 WBEM_S_FALSE）耗尽后原样返回，不误报错误
    {
        std::vector<IWbemClassObject*> items = { &a, &b };
        CReplayEnum e(std::move(items));
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && obj == &a);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && obj == &b);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_FALSE && ret == 0);
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_FALSE && ret == 0); // 幂等
    }

    // 场景 4：克隆保留枚举位置与终止状态
    {
        std::vector<IWbemClassObject*> items = { &a, &b };
        CReplayEnum e(std::move(items), 0, E_ACCESSDENIED);
        CHECK(e.Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && obj == &a);
        if (obj) { obj->Release(); obj = nullptr; }

        IEnumWbemClassObject* clone = nullptr;
        CHECK(e.Clone(&clone) == WBEM_S_NO_ERROR && clone != nullptr);
        CHECK(clone->Next(5000, 1, &obj, &ret) == WBEM_S_NO_ERROR && obj == &b);
        if (obj) { obj->Release(); obj = nullptr; }
        CHECK(clone->Next(5000, 1, &obj, &ret) == E_ACCESSDENIED && ret == 0);
        if (clone) clone->Release();
    }
}

// ----------------------------------------------------------------------------
// QueryInterface 失败路径必须清空输出指针（预置非空哨兵断言）
// ----------------------------------------------------------------------------

static void TestReplayEnumQINullsOut()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CHECK(SUCCEEDED(hr));
    if (FAILED(hr))
        return;

    FakeWbemObject a;
    std::vector<IWbemClassObject*> items = { &a };
    CReplayEnum e(std::move(items));

    void* p = reinterpret_cast<void*>(0x1); // 非空哨兵
    CHECK(e.QueryInterface(IID_IUnknown, &p) == S_OK && p != nullptr);
    static_cast<IUnknown*>(p)->Release();

    p = reinterpret_cast<void*>(0x1);
    CHECK(e.QueryInterface(IID_IEnumWbemClassObject, &p) == S_OK && p != nullptr);
    static_cast<IEnumWbemClassObject*>(p)->Release();

    p = reinterpret_cast<void*>(0x1);
    CHECK(e.QueryInterface(IID_IClientSecurity, &p) == S_OK && p != nullptr);
    static_cast<IClientSecurity*>(p)->Release();

    // 不支持的 IID：E_NOINTERFACE 且输出必为 nullptr
    static const IID kFakeIID = { 0x12345678, 0x1234, 0x1234,
                                  { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } };
    p = reinterpret_cast<void*>(0x1);
    CHECK(e.QueryInterface(kFakeIID, &p) == E_NOINTERFACE && p == nullptr);

    // 委托侧 IID_IMarshal（FTM 聚合）应成功
    p = reinterpret_cast<void*>(0x1);
    CHECK(e.QueryInterface(IID_IMarshal, &p) == S_OK && p != nullptr);
    if (p) static_cast<IMarshal*>(p)->Release();

    CoUninitialize();
}

// ----------------------------------------------------------------------------
// TryWrapLocatorOutput（proxies.h）必须经 QueryInterface 取 IWbemLocator，
// 绝不把请求到的接口指针静态转型了事。
//
// StubLocator 以非虚多继承同时继承 IUnknown 与 IWbemLocator（后者自带另一个
// IUnknown 基），使 QI(IID_IUnknown) 与 QI(IID_IWbemLocator) 返回不同地址——
// 防止真实系统对象"恰好同值布局"掩盖把 IUnknown* 当 IWbemLocator* 用的缺陷。
// （真实 COM 对象须遵守身份规则，不会这样实现；此处只验证 helper 的取接口
// 方式与引用计数守恒，不模拟完整 COM 语义。）无需 CoInitialize：QI 只是
// 本对象内的虚调用。
// ----------------------------------------------------------------------------

// C4584（IUnknown 已是 IWbemLocator 的基类）正是本桩刻意需要的效果：
// 两个身份指针必须返回不同地址。局部压制该警告。
#pragma warning(push)
#pragma warning(disable : 4584)
class StubLocator : public IUnknown, public IWbemLocator
{
    volatile LONG m_ref;

public:
    int connectCalls = 0;

    StubLocator() : m_ref(1) {}
    int refCount() const { return m_ref; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown) {
            *ppv = static_cast<IUnknown*>(this); // 第一基类地址
            AddRef();
            return S_OK;
        }
        if (riid == IID_IWbemLocator) {
            *ppv = static_cast<IWbemLocator*>(this); // 第二基类地址（不同值）
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        return static_cast<ULONG>(InterlockedDecrement(&m_ref)); // 栈对象不 delete
    }

    HRESULT STDMETHODCALLTYPE ConnectServer(
        const BSTR, const BSTR, const BSTR, const BSTR, long, const BSTR,
        IWbemContext*, IWbemServices**) override
    {
        ++connectCalls;
        return S_OK;
    }
};
#pragma warning(pop)

// QI(IID_IWbemLocator) 恒拒的变体：验证 helper 的降级路径
class StubNoLocator : public IUnknown
{
    volatile LONG m_ref;

public:
    StubNoLocator() : m_ref(1) {}
    int refCount() const { return m_ref; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown) {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        return static_cast<ULONG>(InterlockedDecrement(&m_ref));
    }
};

static void TestTryWrapLocatorOutput()
{
    // 成功路径：helper 经 QI 取 Locator 并包装；代理路由 ConnectServer；
    // 引用计数守恒（QI 探查引用 + 构造引用 + punk 输出引用 = 代理单一持有）
    {
        StubLocator stub;
        IUnknown* punk = static_cast<IUnknown*>(&stub); // 模拟 CoCreateInstance 输出（持 1 引用）
        CHECK(punk != static_cast<IWbemLocator*>(&stub)); // 桩前提：两身份指针不同值

        void* wrapped = nullptr;
        CHECK(TryWrapLocatorOutput(punk, &wrapped) == true);
        CHECK(wrapped != nullptr && wrapped != punk); // 输出是代理，不是原指针

        // CWbemLocatorProxy 单继承自 IWbemLocator，IUnknown 身份指针即接口指针
        IWbemLocator* asLocator = static_cast<IWbemLocator*>(wrapped);
        // ppNamespace 传非空输出指针：代理对空输出按 E_POINTER 短路（不路由）
        IWbemServices* svc = nullptr;
        CHECK(asLocator->ConnectServer(nullptr, nullptr, nullptr, nullptr, 0,
                                       nullptr, nullptr, &svc) == S_OK);
        CHECK(stub.connectCalls == 1); // 经代理路由到真实对象
        asLocator->Release(); // 归还代理首引用 -> 代理析构 -> 释放对 stub 的引用
        CHECK(stub.refCount() == 0); // 全部引用恰好平衡
    }

    // 降级路径：对象没有 IWbemLocator（QI 拒绝）-> 返回 false，
    // 输出指针与 punk 引用均保持不动
    {
        StubNoLocator stub;
        IUnknown* punk = static_cast<IUnknown*>(&stub);
        void* wrapped = reinterpret_cast<void*>(0x1); // 非空哨兵
        CHECK(TryWrapLocatorOutput(punk, &wrapped) == false);
        CHECK(wrapped == reinterpret_cast<void*>(0x1)); // 未被写入
        punk->Release(); // helper 未消费 punk 引用：1 -> 0
        CHECK(stub.refCount() == 0);
    }
}

// ----------------------------------------------------------------------------
// m_pos 并发保护。FTM 允许跨单元直连，Next/Reset/Skip/Clone 可从任意线程
// 并发进入。强断言：两线程并发 Next 推进同一枚举器，每个位置恰被消费一次；
// 压力断言：混沌 Reset 线程 + 两线程并发 Clone+drain，每对象至多被消费两次
// （每个克隆独立至多一次），且全程无死锁/崩溃。
// ----------------------------------------------------------------------------

static void TestReplayEnumConcurrency()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CHECK(SUCCEEDED(hr));
    if (FAILED(hr))
        return;

    // 场景 1：并发 Next，2000 个位置每个恰被消费一次
    // 注意所有权：CReplayEnum 析构会 Release 全部缓存对象，因此 new 出的对象
    // 必须在 e 析构之后再 delete（否则对已释放内存虚调用）
    std::vector<FakeWbemObject*> objs1;
    {
        const int kItems = 2000;
        std::vector<IWbemClassObject*> items;
        for (int i = 0; i < kItems; ++i) {
            objs1.push_back(new FakeWbemObject(i)); // Release 到 0 不 delete（见类注释）
            items.push_back(objs1.back());
        }
        CReplayEnum e(std::move(items));

        std::vector<std::atomic<int>> delivered(kItems);
        for (auto& d : delivered) d.store(0);

        auto drainTask = [&](int worker) {
            (void)worker;
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            for (;;) {
                if (e.Next(5000, 1, &obj, &ret) != WBEM_S_NO_ERROR)
                    break;
                auto* fake = static_cast<FakeWbemObject*>(obj); // 单继承布局兼容
                delivered[fake->id].fetch_add(1);
                obj->Release();
                obj = nullptr;
            }
        };
        std::thread t1(drainTask, 1);
        std::thread t2(drainTask, 2);
        t1.join();
        t2.join();

        int total = 0;
        for (int i = 0; i < kItems; ++i) {
            total += delivered[i].load();
            if (delivered[i].load() != 1)
                CHECK(false); // 一次性报告首个偏差
        }
        CHECK(total == kItems);
    } // e 先析构（归还引用计数），随后才可安全 delete

    // 场景 2：混沌 Reset + 并发 Clone + drain
    std::vector<FakeWbemObject*> objs2;
    {
        const int kItems = 500;
        std::vector<IWbemClassObject*> items;
        for (int i = 0; i < kItems; ++i) {
            objs2.push_back(new FakeWbemObject(i));
            items.push_back(objs2.back());
        }
        CReplayEnum e(std::move(items));

        std::vector<std::atomic<int>> delivered(kItems);
        for (auto& d : delivered) d.store(0);

        auto cloneDrain = [&]() {
            IEnumWbemClassObject* cl = nullptr;
            if (e.Clone(&cl) != WBEM_S_NO_ERROR)
                return;
            IWbemClassObject* obj = nullptr;
            ULONG ret = 0;
            for (;;) {
                if (cl->Next(5000, 1, &obj, &ret) != WBEM_S_NO_ERROR)
                    break;
                auto* fake = static_cast<FakeWbemObject*>(obj);
                delivered[fake->id].fetch_add(1);
                obj->Release();
                obj = nullptr;
            }
            cl->Release();
        };
        auto chaos = [&]() {
            for (int i = 0; i < 200; ++i)
                e.Reset(); // 扰动 m_pos：与 Clone 的位置快照并发竞争（压锁）
        };
        std::thread t1(cloneDrain);
        std::thread t2(cloneDrain);
        std::thread t3(chaos);
        t1.join();
        t2.join();
        t3.join();

        bool sane = true;
        for (int i = 0; i < kItems; ++i)
            if (delivered[i].load() > 2)
                sane = false;
        CHECK(sane); // 每对象至多被两克隆各消费一次（混沌 Reset 只影响原枚举器位置）
    } // e 先析构

    for (auto* o : objs1) delete o;
    for (auto* o : objs2) delete o;

    CoUninitialize();
}

// ----------------------------------------------------------------------------
// 构造失败（csinit 故障注入）必须抛出，FTM 与缓存引用恰好释放
// ----------------------------------------------------------------------------

// FTM 引用计数桩：经 g_ftmFactory 接缝替换真实 FTM，使"恰好释放一次"可被
// 计数断言（真实 FTM 的泄漏/双重释放不产生可观测崩溃，断言不出）。
// Release 不 delete（堆对象由测试显式回收，与 FakeWbemObject 栈对象策略区分）。
class FakeFTM : public IUnknown
{
    volatile LONG m_ref;

public:
    FakeFTM() : m_ref(1) {} // 初始计数 1 = 构造函数（punkOuter）持有的那次引用

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown) {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        return static_cast<ULONG>(InterlockedDecrement(&m_ref)); // 不 delete
    }

    LONG RefCount() const { return m_ref; } // 泄漏(=1)/多放(=-1)均可被断言区分
};

static int g_ftmCreated = 0;          // 桩工厂被调用次数
static FakeFTM* g_lastFakeFTM = nullptr;

static HRESULT WINAPI FakeFTMFactory(IUnknown* /*punkOuter*/, IUnknown** ppunk)
{
    ++g_ftmCreated;
    g_lastFakeFTM = new FakeFTM();
    *ppunk = g_lastFakeFTM;
    return S_OK;
}

static void TestReplayEnumConstructorFailure()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    CHECK(SUCCEEDED(hr));
    if (FAILED(hr))
        return;

    FakeWbemObject a, b;
    IWbemClassObject* pa = &a;
    IWbemClassObject* pb = &b;

    // 1) 替换 FTM 工厂为计数桩 + csinit 故障注入：模拟临界区创建失败（发生在
    //    FTM 创建成功之后——正是构造 catch 的清理路径）
    HRESULT (WINAPI* realFactory)(IUnknown*, IUnknown**) = g_ftmFactory;
    g_ftmCreated = 0;
    g_lastFakeFTM = nullptr;
    g_ftmFactory = &FakeFTMFactory;
    SetEnvironmentVariableW(L"WMI_SPOOFER_FAULT", L"csinit");
    bool threw = false;
    {
        std::vector<IWbemClassObject*> items = { pa, pb };
        try {
            CReplayEnum e(std::move(items));
        } catch (const std::bad_alloc&) {
            threw = true; // fail-closed 预期的异常类型
        }
    }
    SetEnvironmentVariableW(L"WMI_SPOOFER_FAULT", nullptr); // 还原，不影响后续用例
    g_ftmFactory = realFactory;

    // 2) 断言：异常类型、FTM 恰好创建一次且恰好释放一次——漏放计数停留 1、
    //    多放降到 -1，均被 ==0 拒绝（不依赖"双重释放会崩溃"的非确定性信号）
    CHECK(threw);
    CHECK(g_ftmCreated == 1);
    if (g_lastFakeFTM) {
        CHECK(g_lastFakeFTM->RefCount() == 0);
        delete g_lastFakeFTM;
        g_lastFakeFTM = nullptr;
    }

    // 3) 缓存引用释放：测试中 fake 的初始计数 1 即移交给 vector/构造函数的引用
    //    （无额外 AddRef），catch 释放后应回落到 0：AddRef 返回 1 = 已回收
    CHECK(pa->AddRef() == 1);
    pa->Release();
    CHECK(pb->AddRef() == 1);
    pb->Release();

    CoUninitialize();
}

// ----------------------------------------------------------------------------

int wmain()
{
    TestStringHelpers();
    TestMaskValue();
    TestEnv();
    TestEmptyToken();
    TestLoadConfig();
    TestParse();
    TestVariantToString();
    TestReplayEnum();
    TestReplayEnumSkip();
    TestReplayEnumTerminalHr();
    TestReplayEnumQINullsOut();
    TestReplayEnumConstructorFailure();
    TestTryWrapLocatorOutput();
    TestReplayEnumConcurrency();

    wprintf(L"%d checks, %d failed\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
