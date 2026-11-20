//! 构建脚本：Windows 下把 icons/icon.ico 嵌入 exe 资源（资源管理器/任务栏图标）。
//! 非 Windows 目标不做任何事；资源编译失败仅告警，不阻断构建。

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("icons/icon.ico");
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=嵌入应用图标失败: {e}");
        }
    }
}
