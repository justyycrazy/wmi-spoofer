//! 注入模块：挂起启动目标程序 -> 跨进程写入 DLL 路径 ->
//! CreateRemoteThread 调用 LoadLibraryW -> 等 DLL 安装线程装好 hook -> 恢复运行。

use std::path::Path;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

// do_inject 与守卫类型用到（函数体内的 use 作用于不到签名）
#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE};

/// 句柄守卫：Drop 时 CloseHandle（RAII：新增错误分支不再依赖手工补清理）
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// 跨进程写入的远程内存（DLL 路径缓冲）。
/// 创建后默认“Drop 即释放”（远程线程尚未启动，缓冲无人读取，可安全回收）；
/// CreateRemoteThread 成功后必须 [`RemoteMem::keep_on_drop`] 转入保守模式——
/// 此后 Drop 不释放（远程线程可能仍在读取路径缓冲，释放构成跨进程 UAF，
/// 内存随子进程终止由系统回收），仅在确认线程结束后显式 [`RemoteMem::free_now`]。
struct RemoteMem {
    hproc: HANDLE,
    ptr: *mut std::ffi::c_void,
    free_on_drop: bool,
}

impl RemoteMem {
    fn keep_on_drop(mut self) -> Self {
        self.free_on_drop = false;
        self
    }

    /// 线程已确认结束：立即释放路径缓冲。
    /// 先关闭 free_on_drop（N-01）：free_now 按值消费 self，函数返回时 Drop
    /// 必然执行——不关标志会导致同一块远程内存被释放两次（或保守模式下
    /// 一次都不释放）；释放失败仍静默忽略（目标进程已异常时的兜底路径）。
    fn free_now(mut self) {
        self.free_on_drop = false;
        unsafe {
            let _ = VirtualFreeEx(self.hproc, self.ptr, 0, MEM_RELEASE);
        }
    }
}

impl Drop for RemoteMem {
    fn drop(&mut self) {
        if self.free_on_drop {
            unsafe {
                let _ = VirtualFreeEx(self.hproc, self.ptr, 0, MEM_RELEASE);
            }
        }
    }
}

/// 注入结果：PID + hook 是否已通过就绪事件确认生效
#[derive(Clone, Copy)]
pub struct InjectResult {
    pub pid: u32,
    /// false = 未确认（安装可能仍在进行或已失败），目标程序照常放行
    pub hook_ready: bool,
}

/// hook 就绪事件名约定：DLL 安装线程以 GetCurrentProcessId 同名创建并置位，
/// 双方由 PID 独立推导，无需额外协议变量。
#[cfg(windows)]
fn hook_ready_event_name(pid: u32) -> Vec<u16> {
    format!(r"Local\wmi-spoofer-ready-{pid}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

/// 等待目标进程内的 DLL 置位 hook 就绪事件。
/// DLL 仅在全部 hook 启用成功后才置位；失败路径不置位 -> 本函数超时返回 false。
/// 超时不阻塞注入：调用方照常恢复主线程，仅向 UI 报告"未确认"。
#[cfg(windows)]
fn wait_hook_ready(pid: u32, budget: Duration) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenEventW, WaitForSingleObject, SYNCHRONIZATION_SYNCHRONIZE,
    };

    let name = hook_ready_event_name(pid);
    let deadline = Instant::now() + budget;
    loop {
        match unsafe {
            OpenEventW(
                SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR::from_raw(name.as_ptr()),
            )
        } {
            Ok(ev) => {
                let remain = deadline.saturating_duration_since(Instant::now());
                let ms = remain.as_millis().min(u32::MAX as u128) as u32;
                let signaled = unsafe { WaitForSingleObject(ev, ms) } == WAIT_OBJECT_0;
                let _ = unsafe { CloseHandle(ev) };
                return signaled;
            }
            Err(_) => {
                // 事件可能尚未创建（安装线程还没跑到）：轮询重试直至预算用尽
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// 构造 CreateProcessW 的 Unicode 环境块：当前进程环境 + 注入变量（覆盖同名），双 NUL 结尾。
/// 现有变量经 OsStr 宽字符直取（Phase 4 输入边界）：to_string_lossy 会把非 Unicode
/// 值替换成占位符从而破坏原值；含 NUL 的键/值无法在环境块中表示，跳过。
#[cfg(windows)]
fn build_env_block(extra: &[(String, String)]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    fn ascii_upper(c: u16) -> u16 {
        if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
            c - 0x20
        } else {
            c
        }
    }
    fn keys_eq(a: &[u16], b: &[u16]) -> bool {
        a.len() == b.len()
            && a.iter()
                .zip(b)
                .all(|(x, y)| ascii_upper(*x) == ascii_upper(*y))
    }

    let mut vars: Vec<(Vec<u16>, Vec<u16>)> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let k: Vec<u16> = k.encode_wide().collect();
            let v: Vec<u16> = v.encode_wide().collect();
            if k.contains(&0) || v.contains(&0) {
                None // NUL 在环境块中无法表示，跳过该变量
            } else {
                Some((k, v))
            }
        })
        .collect();
    for (k, v) in extra {
        let kw: Vec<u16> = k.encode_utf16().collect();
        let vw: Vec<u16> = v.encode_utf16().collect();
        match vars.iter_mut().find(|(ek, _)| keys_eq(ek, &kw)) {
            Some(slot) => slot.1 = vw,
            None => vars.push((kw, vw)),
        }
    }

    let mut block = Vec::new();
    for (k, v) in &vars {
        block.extend_from_slice(k);
        block.push('=' as u16);
        block.extend_from_slice(v);
        block.push(0);
    }
    block.push(0); // 环境块以双 NUL 结尾
    block
}

/// 反复 ResumeThread 直至主线程完全恢复。
/// ResumeThread 返回递减前的挂起计数：0 = 本未挂起，1 = 已完全恢复，
/// 大于 1 = 递减后仍挂起（嵌套挂起，如第三方对主线程加挂）——继续递减直至
/// 不超过 1，有界（16 次）防死循环；u32::MAX = 失败，原样透传不空转。
#[cfg(windows)]
fn resume_fully(mut resume: impl FnMut() -> u32) -> u32 {
    let mut r = resume();
    let mut attempts = 0;
    while r > 1 && r != u32::MAX && attempts < 16 {
        r = resume();
        attempts += 1;
    }
    r
}

#[cfg(windows)]
pub fn launch_and_inject(
    target_exe: &Path,
    dll_path: &Path,
    env_vars: &[(String, String)],
) -> Result<InjectResult, String> {
    launch_and_inject_with_args(target_exe, &[], dll_path, env_vars)
}

/// 带命令行参数版：`args` 逐个原样追加到引号包住的 exe 路径之后（不做再引号处理，
/// 探针自控参数内容）。启动器本体继续走无参的 [`launch_and_inject`]。
#[cfg(windows)]
pub fn launch_and_inject_with_args(
    target_exe: &Path,
    args: &[String],
    dll_path: &Path,
    env_vars: &[(String, String)],
) -> Result<InjectResult, String> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, TerminateProcess, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    /// 路径 -> UTF-16 + 结尾 NUL
    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    // 命令行：目标 exe 路径加引号（含空格路径安全），后接调用方给的参数
    let mut cmd_text = format!("\"{}\"", target_exe.display());
    for a in args {
        cmd_text.push(' ');
        cmd_text.push_str(a);
    }
    let mut cmd_line: Vec<u16> = cmd_text.encode_utf16().collect();
    cmd_line.push(0);
    // 工作目录设为目标程序所在目录
    let workdir = target_exe.parent().unwrap_or_else(|| Path::new("."));
    let workdir_w = wide(workdir);
    let dll_w = wide(dll_path);
    // 注入参数走环境变量：DLL 在目标进程内 GetEnvironmentVariableW 读取
    let env_block = build_env_block(env_vars);

    // 1. CREATE_SUSPENDED 挂起启动
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmd_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            Some(env_block.as_ptr().cast()),
            PCWSTR::from_raw(workdir_w.as_ptr()),
            &si,
            &mut pi,
        )
    }
    .map_err(|e| format!("CreateProcessW 失败: {e}"))?;

    let pid = pi.dwProcessId;

    // 后续任一步失败都要终止这个被挂起的目标进程，避免留下僵尸；
    // 终止本身失败也并入错误信息，不让清理静默失败
    match unsafe { do_inject(pi.hProcess, pi.hThread, pid, &dll_w) } {
        Ok(hook_ready) => Ok(InjectResult { pid, hook_ready }),
        Err(msg) => {
            let term = unsafe { TerminateProcess(pi.hProcess, 1) };
            unsafe {
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
            }
            Err(match term {
                Ok(()) => msg,
                Err(e) => format!("{msg}（且 TerminateProcess 清理失败: {e}）"),
            })
        }
    }
}

/// 2~6 步：写路径、远程 LoadLibraryW、等待完成与 hook 就绪、恢复主线程。
/// 返回 hook 是否已确认生效。
///
/// # Safety
/// 调用方必须持有刚由 CreateProcessW(CREATE_SUSPENDED) 创建的有效句柄。
#[cfg(windows)]
unsafe fn do_inject(
    hproc: HANDLE,
    hthread: HANDLE,
    pid: u32,
    dll_w: &[u16],
) -> Result<bool, String> {
    use windows::core::{s, w};
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, ResumeThread, WaitForSingleObject,
        LPTHREAD_START_ROUTINE,
    };

    // 2. 在目标进程分配内存并写入 DLL 完整路径
    //    RAII（Phase 4）：远程线程启动前 Drop 即释放；启动后转入保守模式（见 RemoteMem）
    let bytes = dll_w.len() * 2;
    let remote = VirtualAllocEx(hproc, None, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if remote.is_null() {
        let e = std::io::Error::last_os_error();
        return Err(format!("VirtualAllocEx 失败: {e}"));
    }
    let mem = RemoteMem {
        hproc,
        ptr: remote,
        free_on_drop: true,
    };
    if let Err(e) = WriteProcessMemory(hproc, remote, dll_w.as_ptr().cast(), bytes, None) {
        return Err(format!("WriteProcessMemory 失败: {e}")); // mem Drop 释放
    }

    // 3. 远程线程调用 kernel32!LoadLibraryW(dll路径)
    let k32 = match GetModuleHandleW(w!("kernel32.dll")) {
        Ok(h) => h,
        Err(e) => return Err(format!("GetModuleHandleW(kernel32) 失败: {e}")), // mem Drop 释放
    };
    let loadlib = match GetProcAddress(k32, s!("LoadLibraryW")) {
        Some(p) => p,
        None => return Err("GetProcAddress(LoadLibraryW) 失败".into()), // mem Drop 释放
    };
    let start: LPTHREAD_START_ROUTINE = std::mem::transmute(loadlib);

    let th = match CreateRemoteThread(hproc, None, 0, start, Some(remote), 0, None) {
        Ok(h) => HandleGuard(h),
        Err(e) => {
            return Err(format!(
                "CreateRemoteThread 失败（目标可能加壳/带反调试拦截远程线程）: {e}"
            ))
        } // mem Drop 释放
    };
    // 远程线程已在跑：缓冲可能仍被读取，转入“Drop 不释放”的保守模式
    let mem = mem.keep_on_drop();

    // 4. 等待 LoadLibraryW 完成（最多 15 秒）
    if WaitForSingleObject(th.0, 15_000) != WAIT_OBJECT_0 {
        // 超时：mem Drop 保持不释放（防跨进程 UAF），内存随子进程终止由系统回收
        return Err("等待 LoadLibraryW 超时（15 秒）".into());
    }
    let mut code: u32 = 0;
    if GetExitCodeThread(th.0, &mut code).is_err() {
        // 线程状态未知：同上，不释放远程内存
        return Err("GetExitCodeThread 失败".into());
    }
    mem.free_now(); // 线程已结束，路径缓冲可安全释放（th 由 HandleGuard 关闭）

    // 线程退出码为截断的 HMODULE（x64 基址高位非零必截断），仅用于判 0 = 加载失败
    if code == 0 {
        return Err(
            "LoadLibraryW 在目标进程中返回 0：请确认 wmi-spoofer.dll 与目标程序位数一致、\
             目标机器具备 VC++ 运行库"
                .into(),
        );
    }

    // 5. 等 DLL 安装线程置位 hook 就绪事件（替代固定 Sleep，慢机/杀软下确定性同步），
    //    超时也照常恢复主线程，仅报告"未确认"
    let hook_ready = wait_hook_ready(pid, Duration::from_secs(5));

    // 恢复失败 = 目标主线程仍挂起，不能当成功上报。resume_fully 已把
    // 嵌套挂起（>1）有界递减到 <=1，因此走到这里 0/1 = 成功；u32::MAX = 失败、
    // 仍 >1 = 16 次递减后第三方还在加挂（病态）——两种情形都走 Err 路径由
    // 调用方终止进程清理。
    // 故障注入（测试用）：WMI_SPOOFER_FAULT 含 "resume" 时模拟失败。
    let resume_failed = std::env::var("WMI_SPOOFER_FAULT")
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("resume"))
        })
        .unwrap_or(false);
    let resumed = resume_fully(|| {
        if resume_failed {
            u32::MAX
        } else {
            ResumeThread(hthread)
        }
    });
    if resumed == u32::MAX {
        let e = std::io::Error::last_os_error();
        return Err(if resume_failed {
            "[fault] 模拟 ResumeThread 失败：目标进程将被终止".into()
        } else {
            format!("ResumeThread 失败（目标主线程仍挂起，进程将被终止）: {e}")
        });
    }
    if resumed > 1 {
        return Err(
            "ResumeThread 有界重试后挂起计数仍 >1（目标主线程仍挂起，进程将被终止）".into(),
        );
    }

    // 6. 收尾：句柄是我们自己创建进程所得，关闭即可（目标进程继续运行）
    let _ = CloseHandle(hthread);
    let _ = CloseHandle(hproc);
    Ok(hook_ready)
}

#[cfg(not(windows))]
pub fn launch_and_inject(
    _target_exe: &Path,
    _dll_path: &Path,
    _env_vars: &[(String, String)],
) -> Result<InjectResult, String> {
    Err("仅支持 Windows".into())
}

#[cfg(not(windows))]
pub fn launch_and_inject_with_args(
    _target_exe: &Path,
    _args: &[String],
    _dll_path: &Path,
    _env_vars: &[(String, String)],
) -> Result<InjectResult, String> {
    Err("仅支持 Windows".into())
}

#[cfg(all(test, windows))]
mod tests {
    use super::{launch_and_inject, launch_and_inject_with_args, resume_fully};
    use std::path::Path;
    use std::time::Duration;

    /// 嵌套挂起（计数 >1）必须递减到完全恢复；失败透传不空转；
    /// 持续 >1 时有界停止（16 次重试）。
    #[test]
    fn resume_fully_loops_until_fully_resumed() {
        // 嵌套挂起：首调返回 3，再调返回 1（完全恢复）——只重试必要次数
        let mut calls = 0;
        let r = resume_fully(|| {
            calls += 1;
            if calls == 1 {
                3
            } else {
                1
            }
        });
        assert_eq!(r, 1);
        assert_eq!(calls, 2);

        // 本就未挂起：单次调用即成功，不重试
        let mut calls = 0;
        assert_eq!(
            resume_fully(|| {
                calls += 1;
                0
            }),
            0
        );
        assert_eq!(calls, 1);

        // 失败（u32::MAX）透传，不空转
        let mut calls = 0;
        assert_eq!(
            resume_fully(|| {
                calls += 1;
                u32::MAX
            }),
            u32::MAX
        );
        assert_eq!(calls, 1);

        // 第三方持续加挂：1 次首发 + 16 次重试后有界停止，返回最后的计数
        let mut calls = 0;
        let r = resume_fully(|| {
            calls += 1;
            2
        });
        assert_eq!(r, 2);
        assert_eq!(calls, 17);
    }

    /// 端到端冒烟测试：以 cmd.exe 为无害目标验证完整注入链路
    /// （挂起启动 -> 写入 DLL 路径 -> 远程 LoadLibraryW -> 等 hook 就绪事件 -> 恢复）。
    /// 前置条件：wmi-spoofer.dll 已构建（默认位于 ../wmi-spoof-dll/）。
    /// 运行：cargo test inject_smoke -- --ignored
    #[test]
    #[ignore = "需要 wmi-spoofer.dll 已构建，且会真实注入一个进程"]
    fn inject_smoke() {
        let dll = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\wmi-spoof-dll\wmi-spoofer.dll");
        assert!(dll.is_file(), "wmi-spoofer.dll 不存在: {}", dll.display());
        let dir = dll.parent().unwrap();

        // 删旧日志；注入参数走环境变量（关闭子进程传播，cmd 不需要）
        let log = dir.join("wmi-spoofer.log");
        let _ = std::fs::remove_file(&log);
        let env_vars = vec![
            ("WMI_SPOOFER_BOARD".to_string(), "SMOKETEST-999".to_string()),
            ("WMI_SPOOFER_CHILDREN".to_string(), "0".to_string()),
            ("WMI_SPOOFER_LOG".to_string(), "1".to_string()),
        ];

        let result = launch_and_inject(Path::new(r"C:\Windows\System32\cmd.exe"), &dll, &env_vars)
            .expect("注入链路失败");
        let pid = result.pid;
        assert!(pid > 0);
        // M6 握手：hook 全部启用后 DLL 置位就绪事件，此处应确认收到
        assert!(result.hook_ready, "hook 就绪事件未确认（安装失败或超时）");

        // 给安装线程留时间写日志
        std::thread::sleep(Duration::from_millis(2000));
        let content = std::fs::read_to_string(&log).expect("wmi-spoofer.log 未生成");
        assert!(
            content.contains("配置加载完成"),
            "日志缺少配置加载记录：\n{content}"
        );
        // M2 脱敏：配置值以"首2…末2<长度N>"形态落盘（SMOKETEST-999 长度 13）
        assert!(
            content.contains("SM…99<长度13>"),
            "日志缺少脱敏后的生效配置记录：\n{content}"
        );
        assert!(
            !content.contains("SMOKETEST-999"),
            "日志明文泄露了配置值：\n{content}"
        );
        assert!(
            content.contains("hook 全部启用成功"),
            "日志缺少 hook 安装记录：\n{content}"
        );

        // 收尾：结束测试用 cmd
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }

    /// 注入探针：向 env WMI_SPOOF_TARGET 指定的 exe 注入并观察假值是否送达。
    /// 设 WMI_SPOOF_DENY=1 则改发 EMPTY 无值参数（验证无值启动：探针应读到 0 实例）。
    /// 前置：wmi-spoofer.dll 已构建；目标为能自证读取结果的 WMI 消费者（wmitest.exe）。
    /// 运行：WMI_SPOOF_TARGET="C:\...\wmitest_fwd.exe" cargo test inject_probe -- --ignored --nocapture
    #[test]
    #[ignore = "手动探针：需要 wmi-spoofer.dll 已构建，且会真实注入一个进程"]
    fn inject_probe() {
        let dll = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\wmi-spoof-dll\wmi-spoofer.dll");
        let target = std::env::var("WMI_SPOOF_TARGET").expect("设置 WMI_SPOOF_TARGET 指向探针 exe");
        assert!(dll.is_file(), "wmi-spoofer.dll 不存在: {}", dll.display());

        // 特征值参数（或 EMPTY 无值参数），注入后由探针的 stdout 直接验证是否读到
        let dir = dll.parent().unwrap();
        let _ = std::fs::remove_file(dir.join("wmi-spoofer.log"));
        let deny = std::env::var("WMI_SPOOF_DENY").is_ok();
        let mut env_vars: Vec<(String, String)> = if deny {
            vec![(
                "WMI_SPOOFER_EMPTY".to_string(),
                "board,cpu,disk".to_string(),
            )]
        } else {
            vec![
                ("WMI_SPOOFER_BOARD".to_string(), "SPOOFBOARD-99".to_string()),
                (
                    "WMI_SPOOFER_CPU".to_string(),
                    "AAAAAAAAAAAAAAAA".to_string(),
                ),
                ("WMI_SPOOFER_DISK".to_string(), "SPOOFDISK-01".to_string()),
            ]
        };
        env_vars.push(("WMI_SPOOFER_CHILDREN".to_string(), "0".to_string()));
        env_vars.push(("WMI_SPOOFER_LOG".to_string(), "1".to_string()));

        let result = launch_and_inject(Path::new(&target), &dll, &env_vars).expect("注入链路失败");
        println!(
            "注入成功 pid={} hook_ready={}",
            result.pid, result.hook_ready
        );
        // 探针自行退出；输出直接打印在本测试的控制台上
        std::thread::sleep(Duration::from_millis(3000));
    }

    /// 注入探针（带命令行参数版）：WMI_SPOOF_TARGET 指定目标 exe，
    /// WMI_SPOOF_ARGS 指定命令行参数（空格切分，不含引号内空格），
    /// WMI_SPOOF_CHILDREN=1 开启子进程传播，WMI_SPOOF_DENY=1 同 inject_probe 发 EMPTY 参数。
    /// 用于覆盖缺口的手动验证：可直接注入 cscript / powershell / wmitest 子命令。
    /// 运行示例：
    ///   WMI_SPOOF_TARGET="C:\Windows\System32\cscript.exe" \
    ///   WMI_SPOOF_ARGS="//nologo C:\...\tools\probe-wbemdisp.vbs" \
    ///   cargo test inject_probe_cmd -- --ignored --nocapture
    #[test]
    #[ignore = "手动探针：需要 wmi-spoofer.dll 已构建，且会真实注入一个进程"]
    fn inject_probe_cmd() {
        let dll = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\wmi-spoof-dll\wmi-spoofer.dll");
        let target = std::env::var("WMI_SPOOF_TARGET").expect("设置 WMI_SPOOF_TARGET 指向探针 exe");
        assert!(dll.is_file(), "wmi-spoofer.dll 不存在: {}", dll.display());

        let dir = dll.parent().unwrap();
        let _ = std::fs::remove_file(dir.join("wmi-spoofer.log"));
        let deny = std::env::var("WMI_SPOOF_DENY").is_ok();
        let mut env_vars: Vec<(String, String)> = if deny {
            vec![(
                "WMI_SPOOFER_EMPTY".to_string(),
                "board,cpu,disk".to_string(),
            )]
        } else {
            vec![
                ("WMI_SPOOFER_BOARD".to_string(), "SPOOFBOARD-99".to_string()),
                (
                    "WMI_SPOOFER_CPU".to_string(),
                    "AAAAAAAAAAAAAAAA".to_string(),
                ),
                ("WMI_SPOOFER_DISK".to_string(), "SPOOFDISK-01".to_string()),
            ]
        };
        env_vars.push((
            "WMI_SPOOFER_CHILDREN".to_string(),
            std::env::var("WMI_SPOOF_CHILDREN").unwrap_or_else(|_| "0".to_string()),
        ));
        env_vars.push(("WMI_SPOOFER_LOG".to_string(), "1".to_string()));

        let args: Vec<String> = std::env::var("WMI_SPOOF_ARGS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();

        let result = launch_and_inject_with_args(Path::new(&target), &args, &dll, &env_vars)
            .expect("注入链路失败");
        println!(
            "注入成功 pid={} hook_ready={}",
            result.pid, result.hook_ready
        );
        // 探针自行退出；输出直接打印在本测试的控制台上。
        // PowerShell 等慢启动目标可用 WMI_SPOOF_WAIT（毫秒）加大等待。
        let wait_ms: u64 = std::env::var("WMI_SPOOF_WAIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        std::thread::sleep(Duration::from_millis(wait_ms));
    }

    /// C2 回归测试：CHILDREN=0 时，注入后的目标自己创建的子进程应正常运行。
    /// 旧缺陷：hook 无条件给子进程追加 CREATE_SUSPENDED 且永不恢复 -> 目标永等。
    /// 目标为 tools\childtest.exe（源码同目录 childtest.cpp，VS 环境构建）：
    /// 它以自身为子进程（退出码 7）并等待之，子进程正常退出后向结果文件写 OK。
    /// 运行：cargo test inject_childtest -- --ignored
    #[test]
    #[ignore = "需要 wmi-spoofer.dll 与 childtest.exe 已构建，且会真实注入一个进程"]
    fn inject_childtest() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\wmi-spoof-dll");
        let dll = base.join("wmi-spoofer.dll");
        let target = base.join(r"tools\childtest.exe");
        assert!(dll.is_file(), "wmi-spoofer.dll 不存在: {}", dll.display());
        assert!(
            target.is_file(),
            "childtest.exe 不存在（先用 VS 环境构建 tools\\childtest.cpp）: {}",
            target.display()
        );

        let result_file =
            std::env::temp_dir().join(format!("wmi-spoofer-childtest-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&result_file);

        let env_vars = vec![
            ("WMI_SPOOFER_CHILDREN".to_string(), "0".to_string()),
            ("WMI_SPOOFER_LOG".to_string(), "1".to_string()),
        ];
        let args = [result_file.to_string_lossy().into_owned()];
        let injected =
            launch_and_inject_with_args(&target, &args, &dll, &env_vars).expect("注入链路失败");
        assert!(injected.hook_ready, "hook 就绪事件未确认");

        // 目标等待其子进程退出码 7；结果文件出现 OK = 子进程未被挂死
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut content = String::new();
        while std::time::Instant::now() < deadline {
            match std::fs::read_to_string(&result_file) {
                Ok(s) => {
                    content = s;
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &injected.pid.to_string(), "/F"])
            .output();
        assert_eq!(content, "OK", "子进程未在期限内正常退出（可能被挂起）");
        let _ = std::fs::remove_file(&result_file);
    }
}
