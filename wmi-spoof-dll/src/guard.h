// ============================================================================
//  guard.h —— Win32 / COM 外部边界的异常隔离
//
//  Detour 与 COM 方法是外部 ABI 边界：new / std::vector / std::wstring / 正则
//  在内存不足等场景抛出的 C++ 异常不得越过边界（否则 terminate 或宿主进程级
//  未定义行为）。把可能抛异常的段放进 GuardHr 的 lambda；无 C++ 分配的纯转发
//  方法（Reset/Skip/QI 等）不会抛异常，无需包裹。
//
//  注意：异常拦截是兜底而非资源管理。lambda 内仍须"先构造成功、再交换输出
//  指针"，并保证抛出点之前持有的 COM 引用在 catch 中撤回（见各调用处）。
// ============================================================================

#pragma once

#include <windows.h>

#include <exception>
#include <utility>

#include "log.h"

// ----------------------------------------------------------------------------
// ScopeGuard：作用域退出时执行回调，用于 COM 引用等无 RAII 资源的
// "任何退出路径恰好清理一次"。成功转移所有权时用 dismiss() 撤销。
// C++17 CTAD：ScopeGuard guard([&]{ ... }); 直接构造。
// ----------------------------------------------------------------------------
template <typename F>
class ScopeGuard
{
public:
    explicit ScopeGuard(F&& f) : f_(std::forward<F>(f)) {}
    explicit ScopeGuard(const F& f) : f_(f) {}
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;

    void dismiss() { active_ = false; }

    ~ScopeGuard()
    {
        if (active_)
            f_();
    }

private:
    F f_;
    bool active_ = true;
};

// HRESULT 边界：fn 抛异常时记日志并返回 fallback。
// 用作 Detour 包装段时传原始 hr 作 fallback（包装失败 = 降级为未包装真实对象，
// 调用方可见结果不变）；用作 COM 方法体时传 E_OUTOFMEMORY。
// catch 内使用不分配、不抛出的 LogFallback：异常处理器自身不得再抛。
template <typename Fn>
inline HRESULT GuardHr(Fn&& fn, HRESULT fallback)
{
    try {
        return fn();
    } catch (const std::exception& e) {
        LogFallback(L"[!] 异常被边界拦截：%hs，返回 hr=0x%08X",
                    e.what(), static_cast<unsigned>(fallback));
    } catch (...) {
        LogFallback(L"[!] 未知异常被边界拦截，返回 hr=0x%08X", static_cast<unsigned>(fallback));
    }
    return fallback;
}
