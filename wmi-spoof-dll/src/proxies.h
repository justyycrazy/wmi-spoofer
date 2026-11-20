// ============================================================================
//  proxies.h —— WMI COM 代理层（覆写辅助 + IWbemServices/IWbemLocator 包装）
//
//  三个同步读路径按注入环境变量（WMI_SPOOFER_*）覆写后返回：
//    · ExecQuery / CreateInstanceEnum：抽干真实枚举器，逐对象覆写，用自制回放
//      枚举器 CReplayEnum（见 replay_enum.h）替代返回；
//    · GetObject：仅实例对象（路径含 '='）在内存副本上覆写；
//  *Async 变体不覆写。IClientSecurity 委托到真实代理（修复 .NET/WMI 消费者在
//  本包装上 CoSetProxyBlanket 失败导致的绑定失败）；封送经显式 IMarshal 转发到
//  真实代理（unmarshal 出真实对象，语义与隐式转发一致）。ConnectServer 的
//  blanket 重设仅在调用方未提供凭据时进行（凭据条件化）。
//
//  本头文件仅被 hooks.cpp 包含（类体逐字保留，便于与原单文件版本对照）。
// ============================================================================
#pragma once

#include <windows.h>
#include <objbase.h>
#include <wbemidl.h>
#include <wbemcli.h>

#include <vector>

#include "common.h"
#include "config.h"
#include "guard.h"
#include "log.h"
#include "parse.h"
#include "replay_enum.h"

// ----------------------------------------------------------------------------
// 属性覆写：对单个结果对象执行 Get(原值) -> Put(假值) 并记录日志。
// 返回 true = 全部规则应用成功；false = 有规则失败（对象仍保留、查询不失败，
// 采用"降级交付"策略——失败经返回值与结构化日志暴露，不静默）
// ----------------------------------------------------------------------------

static bool SpoofObject(IWbemClassObject* obj,
                        const std::wstring& clsDisplay,
                        const std::vector<PropRule>& rules)
{
    bool allOk = true;
    for (const PropRule& rule : rules) {
        VARIANT varOrig;
        VariantInit(&varOrig);
        CIMTYPE ct = CIM_EMPTY;
        HRESULT hGet = obj->Get(rule.name.c_str(), 0, &varOrig, &ct, nullptr);

        std::wstring orig;
        if (SUCCEEDED(hGet)) {
            orig = MaskValue(VariantToString(varOrig)); // 原值脱敏，不落盘真实指纹
        } else {
            orig = L"<取值失败 hr=0x" + [] (HRESULT h) {
                wchar_t b[16]; swprintf(b, 16, L"%08X", static_cast<unsigned>(h));
                return std::wstring(b);
            } (hGet) + L">";
            allOk = false; // 取不到原值：属性缺失/类型不符，覆写大概率不完整
        }

        // 组装 VT_BSTR 假值并写回（Put 只改内存中的这份本地对象副本，不落库）
        VARIANT v;
        VariantInit(&v);
        v.vt = VT_BSTR;
        v.bstrVal = SysAllocString(rule.value.c_str());
        HRESULT hPut = WBEM_E_OUT_OF_MEMORY;
        if (v.bstrVal)
            hPut = obj->Put(rule.name.c_str(), 0, &v, CIM_STRING);
        else
            Log(L"    [!] SysAllocString 失败：%s（跳过 Put）", rule.name.c_str());
        VariantClear(&v);
        if (FAILED(hPut)) {
            allOk = false;
            Log(L"    [!] 规则应用失败：%s（Put hr=0x%08X，该属性保留真实值）",
                rule.name.c_str(), static_cast<unsigned>(hPut));
        }

        // 假值默认同样脱敏，WMI_SPOOFER_LOG_FAKE=1 时记明文（核对送达用）
        const std::wstring shownFake =
            g_logFakePlain ? rule.value : MaskValue(rule.value);
        Log(L"    [%s] %s: '%s' -> '%s' (Put hr=0x%08X)",
            clsDisplay.c_str(), rule.name.c_str(),
            orig.c_str(), shownFake.c_str(), static_cast<unsigned>(hPut));

        VariantClear(&varOrig);
    }
    return allOk;
}

// ----------------------------------------------------------------------------
// 枚举覆写公共尾段：ExecQuery 与 CreateInstanceEnum 命中规则后共用
//
// 输入命中的规则与真实枚举器：设 IMPERSONATE -> 有限超时抽干 -> 逐对象覆写 ->
// 释放真实枚举器 -> 构造回放枚举器。返回的回放枚举器归调用方所有。
// ----------------------------------------------------------------------------

static CReplayEnum* SpoofRealEnum(IEnumWbemClassObject* realEnum, const ClassRule* rule)
{
    // realEnum 所有权由本函数独占——任何退出路径恰好释放一次，调用方
    // 不再参与清理（消除异常路径的重复释放）
    ScopeGuard releaseEnum([&] { realEnum->Release(); });

    // 修复：给真实枚举代理同样设置 IMPERSONATE（Next 阶段的拒绝发生在这一层）
    HRESULT hrBlanket = CoSetProxyBlanket(realEnum, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                                          nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                          RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DEFAULT);
    if (FAILED(hrBlanket))
        Log(L"    [!] 真实枚举器 CoSetProxyBlanket 失败：hr=0x%08X（Next 可能被拒）",
            static_cast<unsigned>(hrBlanket));

    // 把结果全部枚举进 vector：IEnumWbemClassObject 是单向的，
    // 遍历后必须用自制回放枚举器还给调用方。
    // 注意：单向枚举器不允许 WBEM_INFINITE 超时，必须用有限值。
    std::vector<IWbemClassObject*> items;
    // 缓存引用由守卫持有——push_back 抛出或构造回放器抛出时整组撤回；
    // 成功路径 items 已被 move 成空 vector，守卫析构循环为空，无需 dismiss
    ScopeGuard releaseItems([&] {
        for (IWbemClassObject* o : items)
            if (o) o->Release();
    });
    ULONG drained = 0;
    ULONG degraded = 0; // 覆写未完全成功的对象数（降级交付，统计暴露）
    HRESULT termHr = WBEM_S_FALSE; // 干净结束；否则保留原始终止错误（不再吞掉）
    for (;;) {
        IWbemClassObject* obj = nullptr;
        ULONG ret = 0;
        HRESULT h = realEnum->Next(5000, 1, &obj, &ret);
        if (h != WBEM_S_NO_ERROR) {
            if (h != WBEM_S_FALSE) {
                termHr = h;
                Log(L"    [!] 真实枚举中断：hr=0x%08X（已取 %u 个对象），错误将透传给调用方",
                    static_cast<unsigned>(h), drained);
            }
            break; // WBEM_S_FALSE 且无对象：枚举结束
        }
        if (ret == 0 || obj == nullptr)
            break;
        if (!SpoofObject(obj, rule->display, rule->props))
            ++degraded;
        try {
            items.push_back(obj); // Next 交给我们的引用计数由 vector 持有
        } catch (...) {
            obj->Release(); // 入队抛出：当前对象尚无人接管，先释放再上抛
            throw;
        }
        ++drained;
    }
    Log(L"    真实枚举完成：对象数=%u，终止 hr=0x%08X", drained, static_cast<unsigned>(termHr));
    if (degraded)
        Log(L"    [!] 规则应用降级：%u/%u 个对象未完全覆写", degraded, drained);

    // move 后 items 变空：缓存引用已由 CReplayEnum 接管（其析构释放）。
    // 构造抛出时由 releaseItems（构造前抛）/ 构造函数体兜底 catch（构造中抛）
    // 各自负责，引用不重不漏；releaseEnum 析构释放真实枚举器
    return new CReplayEnum(std::move(items), 0, termHr);
}

// ----------------------------------------------------------------------------
// CWbemServicesMarshaler —— services 包装的显式 IMarshal 转发
//
// 原实现（隐式转发）：包装对 QI(IID_IMarshal) 转发 m_real，COM 拿到真实 RPC 代理的
// 标准 marshaler；MarshalInterface 虽收到包装指针 pv，但标准封送写入的是真实
// 代理的对象引用（OBJREF 指向真实 IPID），unmarshal 出未包装的真实
// IWbemServices——跨单元消费伪装静默失效（tools/probe-apartment.cpp 情形 3 实测）。
// 显式化：独立 IMarshal 对象持有真实 IMarshal 并逐一转发（MarshalInterface 的
// pv 原样传递），行为与原实现完全一致；目的不是恢复伪装，而是把该语义收敛到
// 一处、可注释可回归（同探针注入前后对照）。
// ----------------------------------------------------------------------------

class CWbemServicesMarshaler : public IMarshal
{
public:
    explicit CWbemServicesMarshaler(IMarshal* real) : m_real(real), m_ref(1)
    {
        if (m_real) m_real->AddRef();
    }

    // 基类无虚析构，析构函数不能标 override
    ~CWbemServicesMarshaler()
    {
        if (m_real) m_real->Release();
    }

    // ---- IUnknown ----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr; // 失败路径输出 nullptr
        if (riid == IID_IUnknown || riid == IID_IMarshal) {
            *ppv = static_cast<IMarshal*>(this);
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
        ULONG r = static_cast<ULONG>(InterlockedDecrement(&m_ref));
        if (r == 0) delete this;
        return r;
    }

    // ---- IMarshal：全量转发（pv 原样传递，真实标准 marshaler 写真实对象引用）----

    HRESULT STDMETHODCALLTYPE GetUnmarshalClass(REFIID riid, void* pv, DWORD dwDestContext,
                                                void* pvDestCtx, DWORD mshlFlags,
                                                CLSID* pCid) override
    {
        return m_real->GetUnmarshalClass(riid, pv, dwDestContext, pvDestCtx, mshlFlags, pCid);
    }

    HRESULT STDMETHODCALLTYPE GetMarshalSizeMax(REFIID riid, void* pv, DWORD dwDestContext,
                                                void* pvDestCtx, DWORD mshlFlags,
                                                DWORD* pSize) override
    {
        return m_real->GetMarshalSizeMax(riid, pv, dwDestContext, pvDestCtx, mshlFlags, pSize);
    }

    HRESULT STDMETHODCALLTYPE MarshalInterface(IStream* pStm, REFIID riid, void* pv,
                                               DWORD dwDestContext, void* pvDestCtx,
                                               DWORD mshlFlags) override
    {
        return m_real->MarshalInterface(pStm, riid, pv, dwDestContext, pvDestCtx, mshlFlags);
    }

    HRESULT STDMETHODCALLTYPE UnmarshalInterface(IStream* pStm, REFIID riid, void** ppv) override
    {
        // unmarshal 侧实际经由 OBJREF 内 CLSID 对应的真实 marshaler 完成，本方法
        // 不会被 COM 经由本对象调用；保留转发保持接口完整
        return m_real->UnmarshalInterface(pStm, riid, ppv);
    }

    HRESULT STDMETHODCALLTYPE ReleaseMarshalData(IStream* pStm) override
    {
        return m_real->ReleaseMarshalData(pStm);
    }

    HRESULT STDMETHODCALLTYPE DisconnectObject(DWORD dwReserved) override
    {
        return m_real->DisconnectObject(dwReserved);
    }

private:
    IMarshal* m_real; // 真实 RPC 代理的标准 marshaler
    volatile LONG m_ref;
};

// ----------------------------------------------------------------------------
// CWbemServicesProxy —— IWbemServices 代理（23 个方法全部 override）
// ----------------------------------------------------------------------------

class CWbemServicesProxy : public IWbemServices, public IClientSecurity
{
public:
    explicit CWbemServicesProxy(IWbemServices* real)
        : m_real(real), m_sec(nullptr), m_marshaler(nullptr), m_ref(1)
    {
        if (m_real) {
            m_real->AddRef(); // 构造时对真实对象 AddRef
            // 持有真实 RPC 代理的 IClientSecurity：本代理要自己实现该接口
            // （见 QueryInterface 与下方委托），把 blanket 操作落到真实通道。
            // 拿不到（如进程内直连对象）时按"无此接口"处理，不影响转发。
            m_real->QueryInterface(IID_IClientSecurity,
                                   reinterpret_cast<void**>(&m_sec));
            // 显式 IMarshal 转发：持有真实对象的 IMarshal，由独立转发对象应答封送请求
            // （行为与旧的隐式转发完全一致；拿不到时封送退回 E_NOINTERFACE，罕见）
            IMarshal* realMarshal = nullptr;
            if (SUCCEEDED(m_real->QueryInterface(IID_IMarshal,
                                                 reinterpret_cast<void**>(&realMarshal)))) {
                // 构造函数不向外抛异常：OOM 时封送降级为受限语义，不中断绑定
                try {
                    m_marshaler = new CWbemServicesMarshaler(realMarshal);
                } catch (...) {
                    m_marshaler = nullptr;
                    // catch 路径一律用 LogFallback：异常处理器自身不得再抛
                    LogFallback(L"[!] CWbemServicesMarshaler 创建失败（封送退回受限语义）");
                }
                realMarshal->Release(); // 转发对象已持引用，这里只交还探查引用
            }
        }
    }

    // 基类无虚析构，析构函数不能标 override
    ~CWbemServicesProxy()
    {
        if (m_marshaler) m_marshaler->Release(); // 先释放转发对象（内部持真实 IMarshal 独立引用）
        if (m_real) m_real->Release();
        if (m_sec) m_sec->Release();
    }

    // ---- IUnknown ----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr; // 失败路径输出 nullptr（转发分支按契约委托，同样安全）
        if (riid == IID_IUnknown || riid == IID_IWbemServices) {
            *ppv = static_cast<IWbemServices*>(this);
            AddRef();
            return S_OK;
        }
        // IClientSecurity：由本代理实现（真实接口只认它自己的代理指针，
        // 转发出去会被 COM 判定对象身份不一致而失败——.NET/WMI 消费者在
        // CoSetProxyBlanket 阶段因此直接绑定失败）。委托实现见下方四个方法。
        if (riid == IID_IClientSecurity) {
            if (!m_sec)
                return E_NOINTERFACE; // 真实对象本身无此接口（罕见）
            *ppv = static_cast<IClientSecurity*>(this);
            AddRef();
            return S_OK;
        }
        // IID_IMarshal：由 CWbemServicesMarshaler 显式应答。封送行为与
        // 旧的隐式转发完全一致——unmarshal 出真实 IWbemServices，跨单元消费伪装
        // 静默失效（probe-apartment 情形 3）；本实现只把该语义显式化、可注释可回归
        if (riid == IID_IMarshal) {
            if (!m_marshaler)
                return E_NOINTERFACE; // 真实对象无 IMarshal（罕见）：封送退回受限语义
            return m_marshaler->QueryInterface(riid, ppv);
        }
        // 其余接口转发真实对象（调用方拿到的是未包装的原生接口）
        return m_real->QueryInterface(riid, ppv);
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG r = static_cast<ULONG>(InterlockedDecrement(&m_ref));
        if (r == 0) delete this;
        return r;
    }

    // ---- IWbemServices：除 ExecQuery 外全部原样转发 ----

    // 注：本 SDK 中 OpenNamespace 的第 4 参为 IWbemServices**（与旧文档不同）
    HRESULT STDMETHODCALLTYPE OpenNamespace(
        const BSTR strNamespace, long lFlags, IWbemContext* pCtx,
        IWbemServices** ppWorkingNamespace, IWbemCallResult** ppResult) override
    {
        return m_real->OpenNamespace(strNamespace, lFlags, pCtx, ppWorkingNamespace, ppResult);
    }

    HRESULT STDMETHODCALLTYPE CancelAsyncCall(IWbemObjectSink* pSink) override
    {
        return m_real->CancelAsyncCall(pSink);
    }

    HRESULT STDMETHODCALLTYPE QueryObjectSink(
        long lFlags, IWbemObjectSink** ppResponseHandler) override
    {
        return m_real->QueryObjectSink(lFlags, ppResponseHandler);
    }

    // ---- 拦截点：GetObject（脚本层 moniker 单实例、ManagementObject.Get 等的底层调用；
    //      仅实例对象覆写，类定义对象放行）----
    HRESULT STDMETHODCALLTYPE GetObject(
        const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
        IWbemClassObject** ppObject, IWbemCallResult** ppCallResult) override
    {
        Log(L"GetObject: %s (lFlags=0x%08X)",
            (strObjectPath ? strObjectPath : L"(null)"), static_cast<unsigned>(lFlags));

        // 拦截段在异常边界内
        return GuardHr([&]() -> HRESULT {
            // 解析类名并查配置表；未命中、非实例路径或缺输出指针时放行真实数据
            const ClassRule* rule = nullptr;
            if (strObjectPath && ppObject) {
                bool isInstance = false;
                std::wstring cls = ParseObjectPathClass(strObjectPath, &isInstance);
                if (!cls.empty() && isInstance) {
                    auto it = g_rules.find(cls);
                    if (it != g_rules.end() && (!it->second.props.empty() || it->second.denyAll))
                        rule = &it->second;
                }
            }
            if (!rule)
                return m_real->GetObject(strObjectPath, lFlags, pCtx, ppObject, ppCallResult);

            Log(L"GetObject 命中规则类：%s（实例路径）", rule->display.c_str());

            // EMPTY 模式（无值启动）：单实例没有"0 实例"语义，按"查无此实例"处理
            if (rule->denyAll) {
                Log(L"    EMPTY 模式：返回 WBEM_E_NOT_FOUND");
                *ppObject = nullptr;
                return WBEM_E_NOT_FOUND;
            }

            // 照常取真实对象，仅在返回的这份内存副本上 Put 假值（不落库）
            IWbemClassObject* obj = nullptr;
            HRESULT hr = m_real->GetObject(strObjectPath, lFlags, pCtx, &obj, ppCallResult);
            if (FAILED(hr) || !obj) {
                Log(L"    [!] 真实 GetObject 失败：hr=0x%08X", static_cast<unsigned>(hr));
                *ppObject = nullptr;
                return hr;
            }

            try {
                if (!SpoofObject(obj, rule->display, rule->props)) // 降级交付
                    Log(L"    [!] 规则应用降级：单实例未完全覆写（见上方逐条）");
            } catch (...) {
                obj->Release(); // 覆写中途抛异常：释放对象再交由边界转换
                *ppObject = nullptr;
                throw;
            }
            *ppObject = obj; // 真实对象的引用转移给调用方
            return hr;
        }, E_OUTOFMEMORY);
    }

    HRESULT STDMETHODCALLTYPE GetObjectAsync(
        const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        Log(L"GetObjectAsync: %s (lFlags=0x%08X)",
            (strObjectPath ? strObjectPath : L"(null)"), static_cast<unsigned>(lFlags));
        return m_real->GetObjectAsync(strObjectPath, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE PutClass(
        IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx,
        IWbemCallResult** ppCallResult) override
    {
        return m_real->PutClass(pObject, lFlags, pCtx, ppCallResult);
    }

    HRESULT STDMETHODCALLTYPE PutClassAsync(
        IWbemClassObject* pObject, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->PutClassAsync(pObject, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE DeleteClass(
        const BSTR strClassPath, long lFlags, IWbemContext* pCtx,
        IWbemCallResult** ppCallResult) override
    {
        return m_real->DeleteClass(strClassPath, lFlags, pCtx, ppCallResult);
    }

    HRESULT STDMETHODCALLTYPE DeleteClassAsync(
        const BSTR strClassPath, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->DeleteClassAsync(strClassPath, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE CreateClassEnum(
        const BSTR strSuperclass, long lFlags, IWbemContext* pCtx,
        IEnumWbemClassObject** ppEnum) override
    {
        return m_real->CreateClassEnum(strSuperclass, lFlags, pCtx, ppEnum);
    }

    HRESULT STDMETHODCALLTYPE CreateClassEnumAsync(
        const BSTR strSuperclass, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->CreateClassEnumAsync(strSuperclass, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE PutInstance(
        IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx,
        IWbemCallResult** ppCallResult) override
    {
        return m_real->PutInstance(pInst, lFlags, pCtx, ppCallResult);
    }

    HRESULT STDMETHODCALLTYPE PutInstanceAsync(
        IWbemClassObject* pInst, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->PutInstanceAsync(pInst, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE DeleteInstance(
        const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
        IWbemCallResult** ppCallResult) override
    {
        return m_real->DeleteInstance(strObjectPath, lFlags, pCtx, ppCallResult);
    }

    HRESULT STDMETHODCALLTYPE DeleteInstanceAsync(
        const BSTR strObjectPath, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->DeleteInstanceAsync(strObjectPath, lFlags, pCtx, pResponseHandler);
    }

    // ---- 拦截点：CreateInstanceEnum（SWbemServices.InstancesOf、
    //      ManagementClass.GetInstances 等枚举读取的底层调用）----
    HRESULT STDMETHODCALLTYPE CreateInstanceEnum(
        const BSTR strFilter, long lFlags, IWbemContext* pCtx,
        IEnumWbemClassObject** ppEnum) override
    {
        Log(L"CreateInstanceEnum: %s (lFlags=0x%08X)",
            (strFilter ? strFilter : L"(null)"), static_cast<unsigned>(lFlags));

        if (!ppEnum)
            return m_real->CreateInstanceEnum(strFilter, lFlags, pCtx, ppEnum);

        // 拦截段在异常边界内：先清空输出指针，抛出时调用方拿到确定的 null
        return GuardHr([&]() -> HRESULT {
            *ppEnum = nullptr;

            // strFilter 即 WMI 类名（无路径无正则），小写后查配置表；无匹配放行真实数据
            const ClassRule* rule = nullptr;
            if (strFilter && *strFilter) {
                auto it = g_rules.find(ToLower(strFilter));
                if (it != g_rules.end() && (!it->second.props.empty() || it->second.denyAll))
                    rule = &it->second;
            }
            if (!rule)
                return m_real->CreateInstanceEnum(strFilter, lFlags, pCtx, ppEnum);

            Log(L"CreateInstanceEnum 命中规则类：%s", rule->display.c_str());

            // EMPTY 模式（无值启动）：与 ExecQuery 对齐，直接返回 0 实例（不调真实 API）
            if (rule->denyAll) {
                Log(L"    EMPTY 模式：返回 0 实例");
                *ppEnum = new CReplayEnum(std::vector<IWbemClassObject*>());
                return S_OK;
            }

            // 先照常调用真实 CreateInstanceEnum
            IEnumWbemClassObject* realEnum = nullptr;
            HRESULT hr = m_real->CreateInstanceEnum(strFilter, lFlags, pCtx, &realEnum);
            if (FAILED(hr) || !realEnum) {
                Log(L"    [!] 真实 CreateInstanceEnum 失败：hr=0x%08X", static_cast<unsigned>(hr));
                *ppEnum = nullptr;
                return hr;
            }

            // 抽干覆写后以回放枚举器替代（与 ExecQuery 共用 SpoofRealEnum）。
            // realEnum 所有权已移交 SpoofRealEnum 内部守卫，此处不再参与
            // 释放（异常路径重复释放的根源已移除）；抛出直接交由外层边界转换
            *ppEnum = SpoofRealEnum(realEnum, rule);
            return hr;
        }, E_OUTOFMEMORY);
    }

    HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(
        const BSTR strFilter, long lFlags, IWbemContext* pCtx,
        IWbemObjectSink* pResponseHandler) override
    {
        Log(L"CreateInstanceEnumAsync: %s (lFlags=0x%08X)",
            (strFilter ? strFilter : L"(null)"), static_cast<unsigned>(lFlags));
        return m_real->CreateInstanceEnumAsync(strFilter, lFlags, pCtx, pResponseHandler);
    }

    // ---- 核心拦截点：ExecQuery ----
    HRESULT STDMETHODCALLTYPE ExecQuery(
        const BSTR strQueryLanguage, const BSTR strQuery, long lFlags,
        IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override
    {
        Log(L"ExecQuery: %s (lFlags=0x%08X)",
            (strQuery ? strQuery : L"(null)"), static_cast<unsigned>(lFlags));

        if (!ppEnum)
            return m_real->ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);

        // 拦截段在异常边界内：先清空输出指针，抛出时调用方拿到确定的 null
        return GuardHr([&]() -> HRESULT {
            *ppEnum = nullptr;

            // 解析类名并查配置表；无匹配则放行真实数据
            std::wstring cls = ParseQueryClass(strQuery);
            const ClassRule* rule = nullptr;
            if (!cls.empty()) {
                auto it = g_rules.find(cls);
                if (it != g_rules.end() && (!it->second.props.empty() || it->second.denyAll))
                    rule = &it->second;
            }
            if (!rule)
                return m_real->ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);

            Log(L"ExecQuery 命中规则类：%s", rule->display.c_str());

            // EMPTY 模式（无值启动）：直接返回 0 实例，目标程序采集不到任何值，
            // 将走它自己的无值回退逻辑
            if (rule->denyAll) {
                Log(L"    EMPTY 模式：返回 0 实例");
                *ppEnum = new CReplayEnum(std::vector<IWbemClassObject*>());
                return S_OK;
            }

            // 先照常调用真实 ExecQuery
            IEnumWbemClassObject* realEnum = nullptr;
            HRESULT hr = m_real->ExecQuery(strQueryLanguage, strQuery, lFlags, pCtx, &realEnum);
            if (FAILED(hr) || !realEnum) {
                Log(L"    [!] 真实 ExecQuery 失败：hr=0x%08X", static_cast<unsigned>(hr));
                *ppEnum = nullptr;
                return hr;
            }

            // 抽干覆写后以回放枚举器替代（与 CreateInstanceEnum 共用 SpoofRealEnum）。
            // realEnum 所有权已移交 SpoofRealEnum 内部守卫，注释同上
            *ppEnum = SpoofRealEnum(realEnum, rule);
            return hr;
        }, E_OUTOFMEMORY);
    }

    HRESULT STDMETHODCALLTYPE ExecQueryAsync(
        const BSTR strQueryLanguage, const BSTR strQuery, long lFlags,
        IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override
    {
        Log(L"ExecQueryAsync: %s (lFlags=0x%08X)",
            (strQuery ? strQuery : L"(null)"), static_cast<unsigned>(lFlags));
        return m_real->ExecQueryAsync(strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE ExecNotificationQuery(
        const BSTR strQueryLanguage, const BSTR strQuery, long lFlags,
        IWbemContext* pCtx, IEnumWbemClassObject** ppEnum) override
    {
        return m_real->ExecNotificationQuery(strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
    }

    HRESULT STDMETHODCALLTYPE ExecNotificationQueryAsync(
        const BSTR strQueryLanguage, const BSTR strQuery, long lFlags,
        IWbemContext* pCtx, IWbemObjectSink* pResponseHandler) override
    {
        return m_real->ExecNotificationQueryAsync(strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
    }

    HRESULT STDMETHODCALLTYPE ExecMethod(
        const BSTR strObjectPath, const BSTR strMethodName, long lFlags,
        IWbemContext* pCtx, IWbemClassObject* pInParams,
        IWbemClassObject** ppOutParams, IWbemCallResult** ppCallResult) override
    {
        return m_real->ExecMethod(strObjectPath, strMethodName, lFlags, pCtx,
                                  pInParams, ppOutParams, ppCallResult);
    }

    HRESULT STDMETHODCALLTYPE ExecMethodAsync(
        const BSTR strObjectPath, const BSTR strMethodName, long lFlags,
        IWbemContext* pCtx, IWbemClassObject* pInParams,
        IWbemObjectSink* pResponseHandler) override
    {
        return m_real->ExecMethodAsync(strObjectPath, strMethodName, lFlags, pCtx,
                                       pInParams, pResponseHandler);
    }

    // ---- IClientSecurity：委托到真实代理（本包装"就是"调用方的 IClientSecurity）----
    // CoSetProxyBlanket/CoQueryProxyBlanket/CoCopyProxy 落在本包装上时，combase 会
    // QI 出本接口并调用下列方法；pProxy 是调用方最初传入的接口指针（通常就是本
    // 包装），需先解包成 m_real 再交给真实代理，否则真实代理的身份校验会拒绝。

    // 识别调用方传回的指针是否为本包装（按 IUnknown 身份比较），是则换成真实代理
    IUnknown* UnwrapProxyArg(IUnknown* p)
    {
        if (!p || !m_real)
            return p;
        IUnknown* identity = nullptr;
        if (SUCCEEDED(p->QueryInterface(IID_IUnknown,
                                        reinterpret_cast<void**>(&identity)))) {
            const bool isOurs =
                (identity == static_cast<IUnknown*>(static_cast<IWbemServices*>(this)));
            identity->Release();
            if (isOurs)
                return static_cast<IUnknown*>(m_real);
        }
        return p;
    }

    HRESULT STDMETHODCALLTYPE QueryBlanket(
        IUnknown* pProxy, DWORD* pAuthnSvc, DWORD* pAuthzSvc,
        OLECHAR** pServerPrincName, DWORD* pAuthnLevel, DWORD* pImpLevel,
        void** pAuthInfo, DWORD* pCapabilites) override
    {
        if (!m_sec) return E_NOINTERFACE;
        return m_sec->QueryBlanket(UnwrapProxyArg(pProxy), pAuthnSvc, pAuthzSvc,
                                   pServerPrincName, pAuthnLevel, pImpLevel,
                                   pAuthInfo, pCapabilites);
    }

    HRESULT STDMETHODCALLTYPE SetBlanket(
        IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc,
        OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel,
        void* pAuthInfo, DWORD dwCapabilities) override
    {
        if (!m_sec) return E_NOINTERFACE;
        return m_sec->SetBlanket(UnwrapProxyArg(pProxy), dwAuthnSvc, dwAuthzSvc,
                                 pServerPrincName, dwAuthnLevel, dwImpLevel,
                                 pAuthInfo, dwCapabilities);
    }

    HRESULT STDMETHODCALLTYPE CopyProxy(IUnknown* pProxy, IUnknown** ppCopy) override
    {
        if (!m_sec) return E_NOINTERFACE;
        if (!ppCopy) return E_POINTER;
        return GuardHr([&]() -> HRESULT {
            *ppCopy = nullptr;
            IUnknown* realCopy = nullptr;
            HRESULT hr = m_sec->CopyProxy(UnwrapProxyArg(pProxy), &realCopy);
            if (FAILED(hr) || !realCopy)
                return hr;
            // 副本若是 IWbemServices 则重新包装，保持拦截与 blanket 委托链
            // （副本的安全设置独立于本包装）；其他接口原样透传
            IWbemServices* asServices = nullptr;
            if (SUCCEEDED(realCopy->QueryInterface(IID_IWbemServices,
                                                   reinterpret_cast<void**>(&asServices)))) {
                CWbemServicesProxy* wrapped;
                try {
                    wrapped = new CWbemServicesProxy(asServices);
                } catch (...) {
                    asServices->Release(); // 包装构造抛出：撤回两处引用再交由边界转换
                    realCopy->Release();
                    throw;
                }
                asServices->Release();
                realCopy->Release();
                // 双重基类下 IUnknown* 必须显式走 IWbemServices 侧（身份指针）
                *ppCopy = static_cast<IUnknown*>(static_cast<IWbemServices*>(wrapped));
                return hr;
            }
            *ppCopy = realCopy; // 透传：引用转移给调用方
            return hr;
        }, E_OUTOFMEMORY);
    }

private:
    IWbemServices* m_real;
    IClientSecurity* m_sec; // 真实代理的 IClientSecurity（构造时 QI，可空）
    IMarshal* m_marshaler;  // 显式 IMarshal 转发对象（构造时创建，可空）
    volatile LONG m_ref;
};

// ----------------------------------------------------------------------------
// CWbemLocatorProxy —— IWbemLocator 代理
// ----------------------------------------------------------------------------

class CWbemLocatorProxy : public IWbemLocator
{
public:
    explicit CWbemLocatorProxy(IWbemLocator* real) : m_real(real), m_ref(1)
    {
        if (m_real) m_real->AddRef(); // 构造时对真实对象 AddRef
    }

    // 基类无虚析构，析构函数不能标 override
    ~CWbemLocatorProxy()
    {
        if (m_real) m_real->Release();
    }

    // ---- IUnknown ----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr; // 失败路径输出 nullptr（转发分支按契约委托，同样安全）
        if (riid == IID_IUnknown || riid == IID_IWbemLocator) {
            *ppv = static_cast<IWbemLocator*>(this);
            AddRef();
            return S_OK;
        }
        return m_real->QueryInterface(riid, ppv);
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG r = static_cast<ULONG>(InterlockedDecrement(&m_ref));
        if (r == 0) delete this;
        return r;
    }

    // ---- IWbemLocator ----
    HRESULT STDMETHODCALLTYPE ConnectServer(
        const BSTR strNetworkResource, const BSTR strUser, const BSTR strPassword,
        const BSTR strLocale, long lSecurityFlags, const BSTR strAuthority,
        IWbemContext* pCtx, IWbemServices** ppNamespace) override
    {
        Log(L"ConnectServer: %s", (strNetworkResource ? strNetworkResource : L"(null)"));
        if (!ppNamespace)
            return E_POINTER;
        // 拦截段在异常边界内：先清空输出指针，抛出时调用方拿到确定的 null
        return GuardHr([&]() -> HRESULT {
            *ppNamespace = nullptr;

            IWbemServices* real = nullptr;
            HRESULT hr = m_real->ConnectServer(strNetworkResource, strUser, strPassword,
                                               strLocale, lSecurityFlags, strAuthority,
                                               pCtx, &real);
            if (FAILED(hr) || !real)
                return hr;

            // 关键修复：显式给真实 services 的 RPC 代理设置 IMPERSONATE。
            // 我们返回的是自己的包装对象，上层（wbemdisp 等）随后对"返回指针"做的
            // CoSetProxyBlanket 会落在这层原生对象上而不是真实 RPC 代理上、静默失效，
            // 真实代理保持进程默认（IDENTIFY），Next 阶段被 WMI 拒绝（WBEM_E_ACCESS_DENIED）。
            //
            // 凭据条件化：仅当调用方未提供凭据时才重设 blanket。实测（tools/
            // probe-blanket.cpp credcheck）：本地命名空间在 ConnectServer 阶段就拒绝显式凭据
            // （WBEM_E_LOCAL_CREDENTIALS），故本地场景恒走 else 分支（行为与旧版一致）；
            // strUser 非空属远程场景防御——避免把调用方凭据的代理重置回进程默认
            // （远程效果本环境无法端到端验证，仅为代码路径正确的防御性收口）。
            if (strUser != nullptr && *strUser != L'\0') {
                Log(L"ConnectServer 跳过 blanket 重设（调用方提供凭据）");
            } else {
                HRESULT hrBlanket = CoSetProxyBlanket(real, RPC_C_AUTHN_DEFAULT,
                                                      RPC_C_AUTHZ_DEFAULT, nullptr,
                                                      RPC_C_AUTHN_LEVEL_DEFAULT,
                                                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
                                                      EOAC_DEFAULT);
                Log(L"ConnectServer CoSetProxyBlanket hr=0x%08X", static_cast<unsigned>(hrBlanket));
            }

            // 用代理包装后返回；构造内部 AddRef，这里把原始输出指针的那次引用释放掉
            CWbemServicesProxy* proxy;
            try {
                proxy = new CWbemServicesProxy(real);
            } catch (...) {
                real->Release(); // 包装构造抛出：撤回本函数对真实对象的引用
                throw;
            }
            *ppNamespace = proxy;
            real->Release();

            Log(L"ConnectServer 已包装 IWbemServices");
            return hr;
        }, E_OUTOFMEMORY);
    }

private:
    IWbemLocator* m_real;
    volatile LONG m_ref;
};

// ----------------------------------------------------------------------------
// 包装 CLSID_WbemLocator 的返回对象（CoCreateInstance / Ex 两条路径共用）
//
// 调用方可能直接请求 IID_IWbemLocator，也可能请求 IID_IUnknown 后再 QI——
// COM 不保证同一对象的 IUnknown* 与 IWbemLocator* 指针同值（多继承、接口
// 代理布局各异），因此一律经 QueryInterface 取 IWbemLocator，绝不把返回
// 指针静态转型了事。
// ----------------------------------------------------------------------------

// punk：CoCreateInstance(Ex) 交给调用方的接口指针（其一次引用由本函数处理）。
// 成功：消费 punk 引用（转移给代理）、*ppvOut = 代理（IUnknown 兼容指针）、
//       返回 true；
// QI 失败（返回对象并非 Locator，理论外情形）：返回 false，punk 引用与
//       *ppvOut 均不动——调用方按未包装降级处理，可见 hr 保持原值；
// new 抛出：QI 探查引用由守卫撤回，punk 引用不动，异常交由外层边界转换。
static bool TryWrapLocatorOutput(IUnknown* punk, void** ppvOut)
{
    IWbemLocator* real = nullptr;
    if (FAILED(punk->QueryInterface(IID_IWbemLocator,
                                    reinterpret_cast<void**>(&real))) || !real)
        return false;
    ScopeGuard releaseQI([&] { real->Release(); }); // 探查引用：成功/抛出路径均撤回
    CWbemLocatorProxy* proxy = new CWbemLocatorProxy(real); // 构造内 AddRef（独立引用）
    punk->Release(); // 调用方输出引用转移为代理生命周期的首引用
    *ppvOut = static_cast<IUnknown*>(static_cast<IWbemLocator*>(proxy));
    return true;
}
