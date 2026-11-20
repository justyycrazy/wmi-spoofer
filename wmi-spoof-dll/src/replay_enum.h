// ============================================================================
//  replay_enum.h —— 回放枚举器（ExecQuery / CreateInstanceEnum 共用）
//
//  IEnumWbemClassObject 是单向枚举器：遍历完无法"还给"调用方，所以必须把
//  原始结果一次性抽干、覆写后存进 vector，再用本类按序回放。
//
//  跨单元封送（FTM 聚合）：本类是纯内存回放对象（结果已抽干覆写，无自有 RPC
//  通道），聚合 FTM 后同进程跨单元封送 unmarshal 出的代理直连本对象，回放语义
//  （含覆写后的假值）随之存活。背景：注入前原生枚举器可跨单元封送使用，初版
//  回放枚举器（无 FTM）跨单元首次 Next 即失败 0x80010012——属注入引入的功能
//  回归，已聚合 FTM 修复（tools/probe-apartment.cpp 情形 4 实测）。FTM 创建失败
//  时降级为旧语义（封送受限），仅记日志，不影响对象其余功能。
// ============================================================================
#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <wbemcli.h>

#include <new>
#include <vector>

#include "guard.h"
#include "config.h"
#include "log.h"

// ----------------------------------------------------------------------------
// INonDelegatingUnknown —— 聚合 FTM 所需的非委托 IUnknown 身份
//
// 聚合规范要求 inner（CoCreateFreeThreadedMarshaler）的 punkOuter 必须是
// outer 的"非委托" IUnknown，否则 inner 的身份查询会回环到委托侧造成身份混乱。
// 本对象自身是聚合者（非被聚合体），委托 QI 与 ND QI 的差异仅在于 IID_IMarshal
// 的路由，故用最小 ND 接口承载非委托身份；其三方法签名与 IUnknown 一致，
// 可将该指针按 ATL 惯例交给 FTM 作 opaque controlling unknown（见实现处注释）。
// ----------------------------------------------------------------------------

class INonDelegatingUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE NDQueryInterface(REFIID riid, void** ppv) = 0;
    virtual ULONG STDMETHODCALLTYPE NDAddRef() = 0;
    virtual ULONG STDMETHODCALLTYPE NDRelease() = 0;

protected:
    ~INonDelegatingUnknown() {} // 接口不拥有对象生命周期，删除一律走 NDRelease
};

// ----------------------------------------------------------------------------
// FTM 创建接缝（可测试性）：CReplayEnum 构造经此函数指针创建聚合 FTM，默认指向
// 真实 CoCreateFreeThreadedMarshaler。仅测试进程把它替换为引用计数桩，使
// "构造失败路径恰好释放一次 FTM"可被确定性断言（真实 FTM
// 的泄漏/双重释放无崩溃观测，断言不出）；生产路径不感知、不改行为。
// C++17 inline 变量：include 它的各编译单元共享单一实体。
// ----------------------------------------------------------------------------
inline HRESULT WINAPI CoCreateReplayFTMDefault(IUnknown* punkOuter, IUnknown** ppunk)
{
    return CoCreateFreeThreadedMarshaler(punkOuter, ppunk);
}
inline HRESULT (WINAPI* g_ftmFactory)(IUnknown* punkOuter, IUnknown** ppunk) =
    &CoCreateReplayFTMDefault;

class CReplayEnum : public IEnumWbemClassObject, public IClientSecurity,
                    public INonDelegatingUnknown
{
public:
    // start = 克隆起始位置（MSDN：Clone/CopyProxy 应保留当前枚举位置）；
    // endHr = 抽干阶段的原始终止结果：干净结束为 WBEM_S_FALSE，中途失败
    // 则保留该 HRESULT，缓存耗尽后由 Next 幂等透传给调用方。
    // 成员声明顺序保证 m_items 先于 m_pos 初始化，此处可安全引用
    explicit CReplayEnum(std::vector<IWbemClassObject*>&& items, size_t start = 0,
                         HRESULT endHr = WBEM_S_FALSE)
        : m_items(std::move(items)),
          m_pos(start < m_items.size() ? start : m_items.size()),
          m_ref(1), m_pFTM(nullptr), m_endHr(endHr)
    {
        // 构造体一旦抛出，对象视为未构造完成、析构不会被调用——已持有的
        // 资源（move-in 的 m_items、可能已创建的 FTM、可能已初始化的临界区）须在
        // 下方 catch 中释放后再 rethrow，否则整组对象泄漏
        try {
            // punkOuter 必须是"非委托"身份：ND 接口三方法与 IUnknown 签名一致，按 ATL
            // 惯例经 reinterpret 把内部身份指针交给 FTM（FTM 仅把它当 opaque
            // controlling unknown 调用 QI/AddRef/Release 三个方法）。失败不致命：
            // 跨单元封送退回受限语义（IMarshal 查询 E_NOINTERFACE），记录现场便于诊断。
            // 经 g_ftmFactory 接缝创建（见其上方说明）
            HRESULT hrFtm = g_ftmFactory(
                reinterpret_cast<IUnknown*>(static_cast<INonDelegatingUnknown*>(this)),
                &m_pFTM);
            if (FAILED(hrFtm) || !m_pFTM) {
                m_pFTM = nullptr;
                Log(L"[!] CReplayEnum 创建 FTM 失败：hr=0x%08X（跨单元封送退回受限语义）",
                    static_cast<unsigned>(hrFtm));
            }
            // FTM 允许同进程跨单元直连调用，Next/Reset/Skip/Clone 可从任意单元
            // 并发进入，m_pos 必须有锁保护（仅原子引用计数不构成线程安全）。
            // 锁创建失败（极端内存不足）fail-closed：抛出交由外层 GuardHr 转
            // E_OUTOFMEMORY，绝不以无锁状态放行并发对象（数据竞争可致越界读写）
            if (FaultEnabled(L"csinit")) // 故障注入（测试用）：模拟临界区创建失败
            {
                m_csOk = false;
                throw std::bad_alloc();
            }
            m_csOk = InitializeCriticalSectionAndSpinCount(&m_cs, 400) != 0;
            if (!m_csOk)
                throw std::bad_alloc();
        } catch (...) {
            // 构造抛出时析构不运行——临界区（防御性，当前无后续
            // 可抛步骤）、已创建的 FTM 引用、move-in 的缓存对象在此一次性释放
            // 再上抛，交由外层 GuardHr 转 E_OUTOFMEMORY。
            // FTM 聚合句柄的 Release 只递减 FTM 自身计数（聚合 inner 不持 outer
            // 非委托引用，构造期亦无外部客户端），不会经 NDRelease 回环 delete this
            if (m_csOk) {
                DeleteCriticalSection(&m_cs);
                m_csOk = false;
            }
            if (m_pFTM) {
                m_pFTM->Release();
                m_pFTM = nullptr;
            }
            for (IWbemClassObject* o : m_items)
                if (o) o->Release();
            throw;
        }
    }

    // 基类无虚析构，析构函数不能标 override
    ~CReplayEnum()
    {
        if (m_csOk) DeleteCriticalSection(&m_cs);
        if (m_pFTM) m_pFTM->Release(); // FTM 随对象析构释放
        for (IWbemClassObject* o : m_items)
            if (o) o->Release(); // 析构释放全部缓存对象
    }

    // ---- IUnknown（委托侧：接口指针身份）----
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr; // COM 合约要求失败路径输出 nullptr，防调用方残留陈旧指针
        // 封送请求路由给聚合的 FTM：COM 拿到 FTM 的 IMarshal 后，MarshalInterface
        // 会先校验传入指针的 IUnknown 身份与 punkOuter 一致（两者同为下方 ND 身份），
        // 随后写入同进程直引用——unmarshal 出的代理直连本对象
        if (riid == IID_IMarshal)
            return m_pFTM ? m_pFTM->QueryInterface(riid, ppv) : E_NOINTERFACE;
        return NDQueryInterface(riid, ppv);
    }

    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return NDAddRef();
    }

    ULONG STDMETHODCALLTYPE Release() override
    {
        return NDRelease();
    }

    // ---- IUnknown（非委托侧：内部身份）----
    HRESULT STDMETHODCALLTYPE NDQueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr; // 失败路径输出 nullptr（成功分支随后覆盖）
        if (riid == IID_IUnknown) {
            *ppv = reinterpret_cast<IUnknown*>(static_cast<INonDelegatingUnknown*>(this));
            NDAddRef();
            return S_OK;
        }
        if (riid == IID_IEnumWbemClassObject) {
            *ppv = static_cast<IEnumWbemClassObject*>(this);
            NDAddRef();
            return S_OK;
        }
        // IClientSecurity：no-op 实现（见下方方法说明）。没有它，部分消费者
        // （如 wbemdisp）在 services 的 blanket 可用后会尝试把安全设置复制到
        // 枚举器上，CoSetProxyBlanket 对本对象失败会被其升级为整体失败。
        if (riid == IID_IClientSecurity) {
            *ppv = static_cast<IClientSecurity*>(this);
            NDAddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE NDAddRef() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&m_ref));
    }

    ULONG STDMETHODCALLTYPE NDRelease() override
    {
        ULONG r = static_cast<ULONG>(InterlockedDecrement(&m_ref));
        if (r == 0) delete this;
        return r;
    }

    // ---- IEnumWbemClassObject ----
    // 并发约定：锁内只做位置快照与推进，AddRef 与 COM 调用一律在锁外——
    // 调用方持有本对象引用，COM 引用计数保证调用期间对象存活，锁外 AddRef 安全；
    // 锁内不调 COM/日志，规避重入死锁
    HRESULT STDMETHODCALLTYPE Reset() override
    {
        if (m_csOk) EnterCriticalSection(&m_cs);
        m_pos = 0;
        if (m_csOk) LeaveCriticalSection(&m_cs);
        return WBEM_S_NO_ERROR;
    }

    HRESULT STDMETHODCALLTYPE Next(long /*lTimeout*/, ULONG uCount,
                                   IWbemClassObject** apObjects,
                                   ULONG* puReturned) override
    {
        if (!apObjects || !puReturned)
            return WBEM_E_INVALID_PARAMETER;
        return GuardHr([&]() -> HRESULT {
            // 锁内：位置快照与推进。缓存有货先交付（含部分交付）；
            // 只有缓存耗尽才让终止 HRESULT 浮出，位置停在末尾保持幂等
            size_t from = 0;
            ULONG take = 0;
            if (m_csOk) EnterCriticalSection(&m_cs);
            {
                const size_t remain = m_items.size() - m_pos;
                take = (static_cast<size_t>(uCount) < remain) ? uCount
                                                              : static_cast<ULONG>(remain);
                from = m_pos;
                m_pos += take; // 交付即推进（take==0 时位置不变，天然幂等）
            }
            if (m_csOk) LeaveCriticalSection(&m_cs);

            if (take == 0 && uCount > 0) {
                // 缓存耗尽：透传抽干阶段的原始终止错误——调用方得以区分
                // "完整结果"与"中途失败"；干净结束原样返回 WBEM_S_FALSE
                *puReturned = 0;
                return FAILED(m_endHr) ? m_endHr : WBEM_S_FALSE;
            }

            // 锁外：AddRef 并交付
            for (ULONG i = 0; i < take; ++i) {
                apObjects[i] = m_items[from + i];
                apObjects[i]->AddRef();
            }
            *puReturned = take;
            // 实际返回数 == 请求数返回 S_OK，不足返回 S_FALSE
            return (take == uCount) ? WBEM_S_NO_ERROR : WBEM_S_FALSE;
        }, E_OUTOFMEMORY);
    }

    HRESULT STDMETHODCALLTYPE NextAsync(ULONG /*uCount*/, IWbemObjectSink* /*pSink*/) override
    {
        return WBEM_E_NOT_SUPPORTED;
    }

    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** ppEnum) override
    {
        if (!ppEnum) return E_POINTER;
        return GuardHr([&]() -> HRESULT {
            // 仅位置读取需要锁；m_items 构造后只读，AddRef 在锁外安全
            size_t startPos = 0;
            if (m_csOk) EnterCriticalSection(&m_cs);
            startPos = m_pos;
            if (m_csOk) LeaveCriticalSection(&m_cs);

            std::vector<IWbemClassObject*> copy;
            copy.reserve(m_items.size());
            for (IWbemClassObject* o : m_items) {
                if (o) o->AddRef(); // 复制 vector 并逐个 AddRef
                copy.push_back(o);
            }
            CReplayEnum* clone;
            try {
                // 克隆保留当前枚举位置与终止状态
                clone = new CReplayEnum(std::move(copy), startPos, m_endHr);
            } catch (...) {
                // operator new 在构造前抛出：撤回本函数的 AddRef，再交由边界转换
                for (IWbemClassObject* o : copy)
                    if (o) o->Release();
                throw;
            }
            *ppEnum = clone;
            return WBEM_S_NO_ERROR;
        }, E_OUTOFMEMORY);
    }

    HRESULT STDMETHODCALLTYPE Skip(long /*lTimeout*/, ULONG nCount) override
    {
        if (m_csOk) EnterCriticalSection(&m_cs);
        const ULONG remain = static_cast<ULONG>(m_items.size() - m_pos);
        HRESULT hr = WBEM_S_NO_ERROR;
        if (nCount >= remain) {
            m_pos = m_items.size();
            // 官方合约是 nCount 大于剩余数量才返回 WBEM_S_FALSE——恰好跳完
            // （==）是合法操作，应返回 S_OK
            if (nCount > remain)
                hr = WBEM_S_FALSE;
        } else {
            m_pos += nCount;
        }
        if (m_csOk) LeaveCriticalSection(&m_cs);
        return hr;
    }

    // ---- IClientSecurity：no-op 语义 ----
    // 回放枚举器是本地内存对象（结果已抽干覆写），不存在 RPC 通道，安全设置
    // 无实际意义。实现为成功空操作：既满足消费者"把 services 的 blanket 复制
    // 到枚举器"的惯例，又不产生任何跨进程效果。
    HRESULT STDMETHODCALLTYPE QueryBlanket(
        IUnknown* /*pProxy*/, DWORD* pAuthnSvc, DWORD* pAuthzSvc,
        OLECHAR** pServerPrincName, DWORD* pAuthnLevel, DWORD* pImpLevel,
        void** pAuthInfo, DWORD* pCapabilites) override
    {
        if (pAuthnSvc) *pAuthnSvc = RPC_C_AUTHN_NONE;
        if (pAuthzSvc) *pAuthzSvc = RPC_C_AUTHZ_NONE;
        if (pServerPrincName) *pServerPrincName = nullptr;
        if (pAuthnLevel) *pAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
        if (pImpLevel) *pImpLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        if (pAuthInfo) *pAuthInfo = nullptr;
        if (pCapabilites) *pCapabilites = EOAC_NONE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetBlanket(
        IUnknown* /*pProxy*/, DWORD /*dwAuthnSvc*/, DWORD /*dwAuthzSvc*/,
        OLECHAR* /*pServerPrincName*/, DWORD /*dwAuthnLevel*/, DWORD /*dwImpLevel*/,
        void* /*pAuthInfo*/, DWORD /*dwCapabilities*/) override
    {
        return S_OK; // 本地对象：安全设置无效果，报成功
    }

    HRESULT STDMETHODCALLTYPE CopyProxy(IUnknown* /*pProxy*/, IUnknown** ppCopy) override
    {
        if (!ppCopy) return E_POINTER;
        return GuardHr([&]() -> HRESULT {
            // 位置读取加锁，语义与 Clone 一致（副本从当前位置独立枚举）
            size_t startPos = 0;
            if (m_csOk) EnterCriticalSection(&m_cs);
            startPos = m_pos;
            if (m_csOk) LeaveCriticalSection(&m_cs);

            std::vector<IWbemClassObject*> copy;
            copy.reserve(m_items.size());
            for (IWbemClassObject* o : m_items) {
                if (o) o->AddRef();
                copy.push_back(o);
            }
            CReplayEnum* clone;
            try {
                clone = new CReplayEnum(std::move(copy), startPos, m_endHr);
            } catch (...) {
                for (IWbemClassObject* o : copy) // 同 Clone：撤回本函数的 AddRef
                    if (o) o->Release();
                throw;
            }
            *ppCopy = static_cast<IUnknown*>(static_cast<IEnumWbemClassObject*>(clone));
            return S_OK;
        }, E_OUTOFMEMORY);
    }

private:
    std::vector<IWbemClassObject*> m_items;
    size_t m_pos;
    volatile LONG m_ref;
    IUnknown* m_pFTM;  // 聚合的 FTM（punkOuter = 本对象的非委托身份），随对象析构释放
    HRESULT m_endHr;   // 抽干阶段的原始终止结果（WBEM_S_FALSE = 干净结束），见构造函数
    CRITICAL_SECTION m_cs;  // 保护 m_pos（FTM 允许跨单元并发调用枚举方法）
    bool m_csOk = false;
};
