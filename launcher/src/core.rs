//! 业务逻辑：本机真实值查询、覆盖值校验、注入参数（环境变量）构造与启动注入。
//! 界面（app.rs）在后台线程调用这里的函数，避免阻塞 egui 渲染。

/// 本机三类 WMI 真实值（界面预填用）
pub struct RealValues {
    pub board_serial: String,
    pub processor_id: String,
    pub disk_serial: String,
}

/// 启动结果：PID + 实际下发的假值；None = 未覆盖，目标程序读到真实值。
/// deny = true 表示无值启动（EMPTY 参数），三类均未覆盖且参数形式不同。
/// hook_ready = DLL 已通过就绪事件确认 hook 全部启用（false = 未确认，详见日志）。
pub struct LaunchResult {
    pub pid: u32,
    pub deny: bool,
    pub hook_ready: bool,
    pub board_serial: Option<String>,
    pub processor_id: Option<String>,
    pub disk_serial: Option<String>,
}

/// 覆盖值不允许包含换行（环境变量值与日志单行显示要求）
fn check_single_line(field: &str, s: &str) -> Result<(), String> {
    if s.contains('\r') || s.contains('\n') {
        Err(format!("{field} 不能包含换行符"))
    } else {
        Ok(())
    }
}

/// 覆盖值最大长度：WMI 属性值（序列号/ProcessorId）实际长度远小于此，
/// 超长只可能是误输入，且会拉长环境变量与日志行
const MAX_OVERRIDE_LEN: usize = 256;

/// 规范化一个覆盖值：trim 后为空视为未设置（None，不下发变量、走真实值）。
/// 值原样保留（不转大小写、不清洗），才能精确复刻目标机的指纹。
fn norm_override(field: &str, v: Option<String>) -> Result<Option<String>, String> {
    match v.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => {
            check_single_line(field, s)?;
            // 输入边界（Phase 4）：嵌入 NUL 会在环境变量/日志中静默截断值，超长值
            // 毫无意义——都在注入前拦截，不让坏值静默下发
            if s.contains('\0') {
                return Err(format!("{field} 不能包含 NUL 字符"));
            }
            if s.chars().count() > MAX_OVERRIDE_LEN {
                return Err(format!("{field} 过长（最多 {MAX_OVERRIDE_LEN} 字符）"));
            }
            Ok(Some(s.to_string()))
        }
        _ => Ok(None),
    }
}

/// 注入参数：随 CreateProcessW 以环境变量下发给目标进程内的 DLL（键见 env_vars）。
pub struct SpoofConfig {
    /// true = 无值启动：三类 WMI 查询返回 0 实例，假值字段忽略
    pub deny: bool,
    pub board_serial: Option<String>,
    pub processor_id: Option<String>,
    pub disk_serial: Option<String>,
    pub inject_children: bool,
    pub log: bool,
}

impl SpoofConfig {
    /// 构造随 CreateProcessW 下发的环境变量（覆盖同名现有变量）。
    /// 变量不存在 = 该类不做覆写，DLL 放行真实值（安全兜底）。
    pub fn env_vars(&self) -> Vec<(String, String)> {
        fn flag(b: bool) -> String {
            if b {
                "1".into()
            } else {
                "0".into()
            }
        }
        let mut vars = Vec::new();
        if self.deny {
            // 无值启动：三类一律 EMPTY，假值字段不下发
            vars.push(("WMI_SPOOFER_EMPTY".into(), "board,cpu,disk".into()));
        } else {
            for (key, val) in [
                ("WMI_SPOOFER_BOARD", &self.board_serial),
                ("WMI_SPOOFER_CPU", &self.processor_id),
                ("WMI_SPOOFER_DISK", &self.disk_serial),
            ] {
                if let Some(v) = val {
                    vars.push((key.to_string(), v.clone()));
                }
            }
        }
        vars.push(("WMI_SPOOFER_CHILDREN".into(), flag(self.inject_children)));
        vars.push(("WMI_SPOOFER_LOG".into(), flag(self.log)));
        vars
    }
}

/// 查询本机真实指纹值，取值口径与目标程序一致：Win32_Processor.ProcessorId、
/// Win32_BaseBoard.SerialNumber（第一实例）、第一块固定硬盘的 SerialNumber（按 Index 排序）。
/// 直接走 COM 连接 WMI（ROOT\CIMV2），与注入 DLL 拦截的读取路径同源，不派生任何子进程。
#[cfg(windows)]
pub fn real_values() -> Result<RealValues, String> {
    use windows::core::{BSTR, PCWSTR};
    use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Variant::{
        VariantClear, VARIANT, VT_BSTR, VT_EMPTY, VT_I4, VT_NULL,
    };
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY,
    };

    // RPC_C_AUTHN_WINNT / RPC_C_AUTHZ_NONE（固化常量，避免为两个数字引入 Win32_System_Rpc）
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const RPC_C_AUTHZ_NONE: u32 = 0;

    /// COM 初始化守卫：仅当本函数真正完成初始化时，才在析构时配对反初始化
    struct ComInit(bool);
    impl Drop for ComInit {
        fn drop(&mut self) {
            if self.0 {
                unsafe { CoUninitialize() };
            }
        }
    }

    // 后台线程通常未初始化 COM，多线程模型一次成功；
    // 若线程已是别的模型（RPC_E_CHANGED_MODE），按“COM 已初始化”直接使用，不重复初始化
    let _com = match unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) } {
        h if h.is_ok() => ComInit(true),
        h if h == RPC_E_CHANGED_MODE => ComInit(false),
        h => return Err(format!("查询本机真实值失败：CoInitializeEx 返回 {h:?}")),
    };

    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| format!("查询本机真实值失败：创建 WbemLocator 出错 {e}"))?;
    let services: IWbemServices = unsafe {
        locator.ConnectServer(
            &BSTR::from("ROOT\\CIMV2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )
    }
    .map_err(|e| format!("查询本机真实值失败：连接 WMI 出错 {e}"))?;

    // 进程默认 COM 安全级别不足以让 WMI 完成模拟（否则 ExecQuery 报 WBEM_E_ACCESS_DENIED）。
    // 按代理逐个加安全毯（MSDN 客户端标准做法），不调用进程级的 CoInitializeSecurity，
    // 以免影响同进程其它 COM 组件（eframe / rfd 等）。
    fn blanket(proxy: &windows::core::IUnknown) -> windows::core::Result<()> {
        unsafe {
            CoSetProxyBlanket(
                proxy,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
        }
    }
    blanket((&services).into())
        .map_err(|e| format!("查询本机真实值失败：设置 WMI 安全级别出错 {e}"))?;

    /// 执行一条 WQL，按实例顺序读回各实例的指定属性（缺值/空值为 None）
    fn query_props(
        services: &IWbemServices,
        statement: &str,
        props: &[&str],
    ) -> Result<Vec<Vec<Option<String>>>, String> {
        let wql = BSTR::from("WQL");
        let stmt = BSTR::from(statement);
        let enumerator = unsafe { services.ExecQuery(&wql, &stmt, WBEM_FLAG_FORWARD_ONLY, None) }
            .map_err(|e| format!("查询 {statement} 失败: {e}"))?;
        blanket((&enumerator).into()).map_err(|e| format!("枚举 {statement} 失败: {e}"))?;

        let prop_bstrs: Vec<BSTR> = props.iter().map(|p| BSTR::from(*p)).collect();
        let mut rows = Vec::new();
        loop {
            let mut slot = [None::<IWbemClassObject>];
            let mut returned = 0u32;
            // 用有限超时（与 DLL 侧口径一致）；Next 返回 WBEM_S_FALSE（成功但取空）时靠 returned==0 判断
            let hr = unsafe { enumerator.Next(5000, &mut slot, &mut returned) };
            if hr.is_err() {
                return Err(format!("枚举 {statement} 失败: {hr:?}"));
            }
            if returned == 0 {
                break;
            }
            let obj = slot[0].take().expect("Next 成功但未返回对象");

            let mut row = Vec::with_capacity(props.len());
            for (i, prop) in props.iter().enumerate() {
                let mut val = VARIANT::default();
                unsafe { obj.Get(&prop_bstrs[i], 0, &mut val, None, None) }
                    .map_err(|e| format!("读取 {statement}.{prop} 失败: {e}"))?;
                let s = unsafe {
                    let text = match val.Anonymous.Anonymous.vt {
                        // 只借用 VARIANT 内的 BSTR（不接管所有权）：
                        // from_raw 会接管指针并 Drop 时 SysFreeString，
                        // 与下方 VariantClear 构成双重释放
                        VT_BSTR => val.Anonymous.Anonymous.Anonymous.bstrVal.to_string(),
                        VT_I4 => val.Anonymous.Anonymous.Anonymous.lVal.to_string(),
                        VT_NULL | VT_EMPTY => String::new(),
                        _ => String::new(),
                    };
                    let _ = VariantClear(&mut val);
                    text
                };
                row.push(if s.is_empty() { None } else { Some(s) });
            }
            rows.push(row);
        }
        Ok(rows)
    }

    // CPU：显式按 DeviceID（CPU0、CPU1…）取最小者，保证多处理器机器上的确定性与
    // 原 PowerShell 口径（Select-Object -First 1）一致
    let cpu_rows = query_props(
        &services,
        "SELECT ProcessorId, DeviceID FROM Win32_Processor",
        &["ProcessorId", "DeviceID"],
    )?;
    let processor_id = cpu_rows
        .iter()
        .min_by_key(|r| r[1].clone().unwrap_or_default())
        .and_then(|r| r[0].clone())
        .unwrap_or_default();

    // 主板：第一实例
    let board_rows = query_props(
        &services,
        "SELECT SerialNumber FROM Win32_BaseBoard",
        &["SerialNumber"],
    )?;
    let board_serial = board_rows
        .first()
        .and_then(|r| r[0].clone())
        .unwrap_or_default();

    // 磁盘：仅固定硬盘（MediaType == 'Fixed hard disk media'），按 Index 升序取第一块
    let disk_rows = query_props(
        &services,
        "SELECT SerialNumber, Index, MediaType FROM Win32_DiskDrive",
        &["SerialNumber", "Index", "MediaType"],
    )?;
    let disk_serial = disk_rows
        .iter()
        .filter(|r| r[2].as_deref() == Some("Fixed hard disk media"))
        .min_by_key(|r| {
            r[1].as_deref()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(u32::MAX)
        })
        .and_then(|r| r[0].clone())
        .unwrap_or_default();

    Ok(RealValues {
        board_serial,
        processor_id,
        disk_serial,
    })
}

#[cfg(not(windows))]
pub fn real_values() -> Result<RealValues, String> {
    Err("仅支持 Windows".into())
}

/// DLL 版本校验：要求 wmi-spoofer.dll 自带 1.0+ 版本资源（项目版本以 DLL 版本
/// 资源为准，launcher 与 DLL 成对发布——新旧 DLL 行为差异面大，旧 DLL 会
/// "半失效"且无任何提示）。错配在注入前被拦截：缺版本资源或版本低于 1.0 一律拒绝。
#[cfg(windows)]
fn dll_version_check(dll_path: &std::path::Path) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{w, PCWSTR};
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };

    let wide: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let filename = PCWSTR::from_raw(wide.as_ptr());

    unsafe {
        let size = GetFileVersionInfoSizeW(filename, None);
        if size == 0 {
            return Err("wmi-spoofer.dll 缺少版本资源：DLL 版本过旧，\
                        请用最新构建的 wmi-spoofer.dll 替换部署目录中的旧文件"
                .into());
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(filename, None, size, data.as_mut_ptr() as *mut c_void)
            .map_err(|e| format!("读取 DLL 版本信息失败: {e}"))?;

        let mut ffi_ptr: *mut c_void = std::ptr::null_mut();
        let mut ffi_len = 0u32;
        let ok = VerQueryValueW(
            data.as_ptr() as *const c_void,
            PCWSTR::from_raw(w!("\\").as_ptr()),
            &mut ffi_ptr,
            &mut ffi_len,
        );
        if ok.as_bool() && ffi_len as usize >= std::mem::size_of::<VS_FIXEDFILEINFO>() {
            let ffi = &*(ffi_ptr as *const VS_FIXEDFILEINFO);
            // FILEVERSION a,b,c,d -> MS = a<<16 | b，LS = c<<16 | d
            let ver = (
                ffi.dwFileVersionMS >> 16,
                ffi.dwFileVersionMS & 0xffff,
                ffi.dwFileVersionLS >> 16,
            );
            if ver >= (1, 0, 0) {
                return Ok(());
            }
            return Err(format!(
                "wmi-spoofer.dll 版本过旧（{}.{}.{}），需要 ≥ 1.0.0：\
                 新旧 DLL 行为差异较大，请用最新构建的 wmi-spoofer.dll 替换部署目录中的旧文件",
                ver.0, ver.1, ver.2
            ));
        }
        Err("wmi-spoofer.dll 版本资源损坏：DLL 版本过旧，\
             请用最新构建的 wmi-spoofer.dll 替换部署目录中的旧文件"
            .into())
    }
}

#[cfg(not(windows))]
fn dll_version_check(_dll_path: &std::path::Path) -> Result<(), String> {
    Ok(()) // 非 Windows 无此校验（整体功能已不可用）
}

pub fn launch(
    exe_path: String,
    // mode：None/"fake" = 伪值启动（按下发的假值覆写）；"empty" = 无值启动（让目标程序读不到值）
    mode: Option<String>,
    board_serial: Option<String>,
    processor_id: Option<String>,
    disk_serial: Option<String>,
    // 注入选项（界面开关）：子进程传播 / 写运行日志
    inject_children: bool,
    log_enabled: bool,
) -> Result<LaunchResult, String> {
    let deny = matches!(mode.as_deref(), Some("empty"));
    let (board, cpu, disk) = if deny {
        (None, None, None)
    } else {
        (
            norm_override("主板序列号", board_serial)?,
            norm_override("ProcessorId", processor_id)?,
            norm_override("磁盘序列号", disk_serial)?,
        )
    };

    // 定位启动器目录：wmi-spoofer.dll 在这里
    let exe = std::env::current_exe().map_err(|e| format!("无法定位启动器目录: {e}"))?;
    let dir = exe.parent().ok_or("无法定位启动器目录")?;
    let dll = dir.join("wmi-spoofer.dll");
    if !dll.is_file() {
        return Err(format!(
            "未找到 wmi-spoofer.dll：请把编译好的 wmi-spoofer.dll 放到启动器同目录（{}），\
             且与目标程序位数一致",
            dir.display()
        ));
    }
    // 版本校验在注入前拦截新旧 DLL 错配（旧 DLL 会"半失效"且无提示）
    dll_version_check(&dll)?;

    let target = std::path::PathBuf::from(exe_path.trim());
    if !target.is_file() {
        return Err(format!("目标程序不存在：{}", target.display()));
    }

    // 注入参数随环境变量下发，DLL 在目标进程内读取
    let config = SpoofConfig {
        deny,
        board_serial: board.clone(),
        processor_id: cpu.clone(),
        disk_serial: disk.clone(),
        inject_children,
        log: log_enabled,
    };

    // 挂起启动 -> 注入 -> 等 hook 就绪事件 -> 恢复
    let injected = crate::inject::launch_and_inject(&target, &dll, &config.env_vars())?;

    Ok(LaunchResult {
        pid: injected.pid,
        hook_ready: injected.hook_ready,
        deny,
        board_serial: board,
        processor_id: cpu,
        disk_serial: disk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_vars_fake_mode_sets_only_given_values() {
        let cfg = SpoofConfig {
            deny: false,
            board_serial: Some("FAKEMB-123".into()),
            processor_id: Some("CAFEBABE00000456".into()),
            disk_serial: None,
            inject_children: true,
            log: true,
        };
        let v = cfg.env_vars();
        assert!(v.contains(&("WMI_SPOOFER_BOARD".into(), "FAKEMB-123".into())));
        assert!(v.contains(&("WMI_SPOOFER_CPU".into(), "CAFEBABE00000456".into())));
        // 未设置的类不下发变量 = DLL 放行真实值
        assert!(!v.iter().any(|(k, _)| k == "WMI_SPOOFER_DISK"));
        // 伪值模式下不发 EMPTY
        assert!(!v.iter().any(|(k, _)| k == "WMI_SPOOFER_EMPTY"));
        assert!(v.contains(&("WMI_SPOOFER_CHILDREN".into(), "1".into())));
        assert!(v.contains(&("WMI_SPOOFER_LOG".into(), "1".into())));
    }

    #[test]
    fn env_vars_deny_mode_only_empty_list() {
        let cfg = SpoofConfig {
            deny: true,
            board_serial: Some("X".into()),
            processor_id: Some("Y".into()),
            disk_serial: Some("Z".into()),
            inject_children: false,
            log: true,
        };
        let v = cfg.env_vars();
        assert!(v.contains(&("WMI_SPOOFER_EMPTY".into(), "board,cpu,disk".into())));
        // 无值模式忽略全部假值字段
        assert!(!v.iter().any(|(k, _)| matches!(
            k.as_str(),
            "WMI_SPOOFER_BOARD" | "WMI_SPOOFER_CPU" | "WMI_SPOOFER_DISK"
        )));
        assert!(v.contains(&("WMI_SPOOFER_CHILDREN".into(), "0".into())));
    }

    #[test]
    fn norm_override_rejects_nul_and_too_long() {
        assert!(norm_override("主板序列号", Some("AB\0CD".into())).is_err());
        let long = "x".repeat(MAX_OVERRIDE_LEN + 1);
        assert!(norm_override("主板序列号", Some(long)).is_err());
        let exact = "x".repeat(MAX_OVERRIDE_LEN);
        assert_eq!(
            norm_override("主板序列号", Some(exact.clone())).unwrap(),
            Some(exact)
        );
    }

    #[test]
    fn norm_override_trims_and_rejects_newlines() {
        assert_eq!(
            norm_override("磁盘序列号", Some("  FAKEDISK-0001 ".into())).unwrap(),
            Some("FAKEDISK-0001".into())
        );
        assert_eq!(
            norm_override("磁盘序列号", Some("   ".into())).unwrap(),
            None
        );
        assert_eq!(norm_override("磁盘序列号", None).unwrap(), None);
        assert!(norm_override("磁盘序列号", Some("A\r\nB".into())).is_err());
        assert!(norm_override("磁盘序列号", Some("A\nB".into())).is_err());
    }

    /// 端到端冒烟测试：真实走一遍 COM 查询本机指纹。只读查询，不改动系统状态。
    #[test]
    #[cfg(windows)]
    fn real_values_com_smoke() {
        let v = real_values().expect("COM 查询本机真实值不应失败");
        // 值内容随机器而异，只断言无换行等会破坏界面/环境变量的字符
        for (name, s) in [
            ("ProcessorId", &v.processor_id),
            ("BaseBoard SerialNumber", &v.board_serial),
            ("DiskDrive SerialNumber", &v.disk_serial),
        ] {
            assert!(
                !s.contains('\n') && !s.contains('\r'),
                "{name} 含换行: {s:?}"
            );
        }
        // 只输出掩码形态（首2…末2<长度N>，与 DLL 侧 MaskValue 口径一致）：
        // 真实指纹不得进入构建日志
        let mask = |s: &str| {
            let n = s.chars().count();
            if n <= 4 {
                format!("<长度{n}>")
            } else {
                let head: String = s.chars().take(2).collect();
                let tail: String = s.chars().skip(n - 2).collect();
                format!("{head}…{tail}<长度{n}>")
            }
        };
        println!("processor_id={}", mask(&v.processor_id));
        println!("board_serial={}", mask(&v.board_serial));
        println!("disk_serial={}", mask(&v.disk_serial));
    }

    /// DLL 版本校验：正例 = 当前构建的 1.0+ DLL；负例 = 无版本资源的文件。
    /// 两者都缺失时软跳过（正常 cargo test 不依赖 DLL 构建）。
    #[test]
    fn dll_version_check_positive_and_negative() {
        let good = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(r"..\wmi-spoof-dll\wmi-spoofer.dll");
        let nover = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(r"..\wmi-spoof-dll\tests\test_pure.exe");
        if !good.is_file() || !nover.is_file() {
            eprintln!("skip: DLL 或测试探针未构建");
            return;
        }
        assert!(dll_version_check(&good).is_ok(), "1.0+ DLL 应通过版本校验");
        match dll_version_check(&nover) {
            Err(err) => {
                assert!(err.contains("版本过旧"), "拒绝文案应指出版本过旧: {err}");
            }
            Ok(()) => panic!("无版本资源的文件应被拒绝"),
        }
    }
}
