//! egui 界面：目标程序选择、指纹假值输入、伪值/无值启动与状态显示。
//! 真实值预填与启动注入都在后台线程执行，经 mpsc 通道回传结果，
//! UI 线程只做轮询刷新，保证窗口始终可响应。
//!
//! 视觉方向：PCB 电路板——深墨绿基板、铜色操作点、丝印暖白文字；
//! 签名元素是标题旁的指纹螺纹印（painter 手绘同心弧）。

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use egui::{
    pos2, vec2, Color32, CornerRadius, FontFamily, Frame, Layout, Margin, Pos2, RichText, Sense,
    Shape, Stroke, Ui,
};

use crate::core::{real_values, LaunchResult, RealValues};

// ---- 基板配色（PCB：深墨绿基板 / 铜箔 / 丝印白）----
const BG: Color32 = Color32::from_rgb(0x0c, 0x15, 0x12); // 基板
const PANEL: Color32 = Color32::from_rgb(0x11, 0x1e, 0x1a); // 卡片
const WELL: Color32 = Color32::from_rgb(0x09, 0x11, 0x0f); // 输入井 / 控制台
const BORDER: Color32 = Color32::from_rgb(0x24, 0x38, 0x32); // 卡片描边
const TRACE: Color32 = Color32::from_rgb(0x31, 0x47, 0x3f); // 走线灰绿
const TEXT: Color32 = Color32::from_rgb(0xe8, 0xe6, 0xda); // 丝印暖白
const MUTED: Color32 = Color32::from_rgb(0x7e, 0x94, 0x8a); // 次要文字
const COPPER: Color32 = Color32::from_rgb(0xd6, 0x9a, 0x5c); // 铜（操作/强调）
const COPPER_HI: Color32 = Color32::from_rgb(0xe9, 0xb5, 0x7b); // 高亮铜
const OK: Color32 = Color32::from_rgb(0x62, 0xc8, 0x7e); // 成功绿
const ERR: Color32 = Color32::from_rgb(0xe2, 0x73, 0x5d); // 失败橙红

#[derive(Clone, Copy, PartialEq)]
enum StatusKind {
    Neutral,
    Ok,
    Err,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Fake,
    Empty,
}

/// 后台线程 -> UI 线程的消息
enum BgMsg {
    RealValues(Result<RealValues, String>),
    LaunchDone(Result<LaunchResult, String>),
}

/// 启动器设置文件（与 wmi-spoofer.exe 同目录，仅启动器读写；DLL 不读此文件）
const SETTINGS_FILE: &str = "wmi-spoofer.ini";

#[derive(Clone)]
struct Settings {
    exe_path: String,
    inject_children: bool,
    log_enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        // 两个开关缺省全开：onefile 目标需要子进程传播；日志缺省记录
        Self {
            exe_path: String::new(),
            inject_children: true,
            log_enabled: true,
        }
    }
}

fn settings_file() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(SETTINGS_FILE))
}

fn load_settings() -> Settings {
    settings_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| parse_settings(&s))
        .unwrap_or_default()
}

/// 开关值语义与 DLL 端一致："0"/false 视为关，其余视为开
fn parse_flag(v: &str) -> bool {
    !(v == "0" || v.eq_ignore_ascii_case("false"))
}

/// 解析设置文件：`[Settings]` 节内的键值行；键缺失用默认值，未知键忽略
fn parse_settings(content: &str) -> Settings {
    let mut s = Settings::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('[')
            || line.starts_with(';')
            || line.starts_with('#')
        {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            match k.to_ascii_lowercase().as_str() {
                "exe_path" => s.exe_path = v.to_string(),
                "inject_children" => s.inject_children = parse_flag(v),
                "log_enabled" => s.log_enabled = parse_flag(v),
                _ => {}
            }
        }
    }
    s
}

fn write_settings_file(s: &Settings) -> std::io::Result<()> {
    if let Some(f) = settings_file() {
        // 防御性清洗：exe_path 含换行会破坏 ini 行结构（单行输入框挡住了常规来源，此处兜底）
        let exe_path = s.exe_path.replace(['\r', '\n'], " ");
        let content = format!(
            "[Settings]\r\nexe_path={}\r\ninject_children={}\r\nlog_enabled={}\r\n",
            exe_path,
            if s.inject_children { "1" } else { "0" },
            if s.log_enabled { "1" } else { "0" },
        );
        // 原子替换（Phase 4 加固）：先写同目录临时文件再 rename，进程中途被杀
        // 也不会留下半截 ini 被下次启动读到
        let tmp = f.with_extension("ini.tmp");
        std::fs::write(&tmp, &content)?;
        match std::fs::rename(&tmp, &f) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    } else {
        Ok(())
    }
}

/// 字体方案：Bahnschrift（工业 DIN，硬件铭牌感）做拉丁正文/标题，
/// Cascadia Mono（无连字）做序列号与控制台，系统中文字体兜底 CJK。
/// 任一缺失都回退到 egui 默认或下一候选。
fn load_fonts() -> egui::FontDefinitions {
    let mut defs = egui::FontDefinitions::default();

    // 拉丁展示体放最前：标题与数字用 Bahnschrift 渲染
    if let Ok(data) = std::fs::read(r"C:\Windows\Fonts\bahnschrift.ttf") {
        defs.font_data.insert(
            "bahnschrift".into(),
            Arc::new(egui::FontData::from_owned(data)),
        );
        defs.families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "bahnschrift".into());
    }

    // 等宽：Cascadia Mono -> Consolas
    const MONO: [(&str, &str); 2] = [
        ("cascadia-mono", r"C:\Windows\Fonts\CascadiaMono.ttf"),
        ("consolas", r"C:\Windows\Fonts\consola.ttf"),
    ];
    for (name, path) in MONO {
        if let Ok(data) = std::fs::read(path) {
            defs.font_data
                .insert(name.into(), Arc::new(egui::FontData::from_owned(data)));
            defs.families
                .entry(FontFamily::Monospace)
                .or_default()
                .insert(0, name.into());
            break;
        }
    }

    // 中文兜底：追加到两个族末尾
    const CJK: &[&str] = &[
        r"C:\Windows\Fonts\msyh.ttc", // 微软雅黑（Win10/11 自带）
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\Deng.ttf",   // 等线
        r"C:\Windows\Fonts\simhei.ttf", // 黑体
        r"C:\Windows\Fonts\simsun.ttc", // 宋体
    ];
    for (i, path) in CJK.iter().enumerate() {
        if let Ok(data) = std::fs::read(path) {
            defs.font_data.insert(
                format!("cjk{i}"),
                Arc::new(egui::FontData::from_owned(data)),
            );
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                defs.families
                    .entry(family)
                    .or_default()
                    .push(format!("cjk{i}"));
            }
            break;
        }
    }
    defs
}

fn setup_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.extreme_bg_color = WELL; // 输入井背景
    visuals.faint_bg_color = WELL;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = COPPER;
    visuals.selection.stroke = Stroke::new(1.0, BG);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.bg_fill = WELL;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x14, 0x24, 0x1f);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, COPPER);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0x18, 0x2b, 0x25);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, COPPER_HI);
    ctx.set_visuals(visuals);
    ctx.set_fonts(load_fonts());
}

pub struct LauncherApp {
    tx: Sender<BgMsg>,
    rx: Receiver<BgMsg>,

    exe_path: String,
    board: String,
    cpu: String,
    disk: String,
    mode: Mode,
    inject_children: bool,
    log_enabled: bool,

    status: String,
    status_kind: StatusKind,
    launching: bool,

    /// 设置文件最近一次写入失败的原因（下次写成功后清除，UI 提示一次）
    settings_err: Option<String>,

    /// 最近一次注入的 hook 就绪状态：None = 尚未注入过或注入失败（不显示小片）
    hook_state: Option<bool>,

    /// 三个指纹字段是否被用户手动编辑过（board/cpu/disk）。
    /// 后台真实值只回填未编辑字段，慢查询的旧结果不得覆盖用户输入
    edited: [bool; 3],

    /// 是否已收到过一次启动结果（晚到的真实值消息不再改写启动状态行）
    launch_done_seen: bool,
}

impl LauncherApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_style(&cc.egui_ctx);

        let (tx, rx) = mpsc::channel();
        // 启动即后台读取本机真实指纹值，完成后经通道回填输入框
        {
            let tx = tx.clone();
            let ctx = cc.egui_ctx.clone();
            thread::spawn(move || {
                // panic 隔离：保证消息必然回传、UI 不卡死（release 保留 unwind，守卫全程生效）
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(real_values))
                    .unwrap_or_else(|_| Err("后台线程异常退出（panic）".to_string()));
                let _ = tx.send(BgMsg::RealValues(r));
                ctx.request_repaint();
            });
        }

        let settings = load_settings();
        Self {
            tx,
            rx,
            exe_path: settings.exe_path,
            board: String::new(),
            cpu: String::new(),
            disk: String::new(),
            mode: Mode::Empty,
            inject_children: settings.inject_children,
            log_enabled: settings.log_enabled,
            status: "正在读取本机真实指纹值…".into(),
            status_kind: StatusKind::Neutral,
            launching: false,
            settings_err: None,
            hook_state: None,
            edited: [false; 3],
            launch_done_seen: false,
        }
    }

    fn set_status(&mut self, text: String, kind: StatusKind) {
        self.status = text;
        self.status_kind = kind;
    }

    /// 把当前设置（目标路径 + 注入开关）写入设置文件；失败原因在 UI 提示一次
    fn persist_settings(&mut self) {
        let s = Settings {
            exe_path: self.exe_path.clone(),
            inject_children: self.inject_children,
            log_enabled: self.log_enabled,
        };
        self.settings_err = write_settings_file(&s).err().map(|e| e.to_string());
    }

    /// 收割后台线程结果
    fn drain_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                BgMsg::RealValues(Ok(v)) => {
                    // 只回填用户未编辑的字段；状态行仅在"未在启动中且尚未有过
                    // 启动结果"时改写——慢查询的旧消息不得覆盖用户输入或启动状态
                    if !self.edited[0] {
                        self.board = v.board_serial;
                    }
                    if !self.edited[1] {
                        self.cpu = v.processor_id;
                    }
                    if !self.edited[2] {
                        self.disk = v.disk_serial;
                    }
                    if !self.launching && !self.launch_done_seen {
                        self.set_status(
                            "等待操作 — 选择目标程序后注入启动。".into(),
                            StatusKind::Neutral,
                        );
                    }
                }
                BgMsg::RealValues(Err(e)) => {
                    // 与 Ok 分支同口径——启动中或已有启动结果时，晚到的
                    // 读取失败不得改写状态行（否则会覆盖"启动成功/失败"的结论）
                    if !self.launching && !self.launch_done_seen {
                        self.set_status(
                            format!(
                                "[WARN] 自动读取本机真实值失败（可手工填写，留空项 = 使用真实值）：{e}"
                            ),
                            StatusKind::Neutral,
                        );
                    }
                }
                BgMsg::LaunchDone(Ok(r)) => {
                    self.launching = false;
                    self.launch_done_seen = true; // 之后晚到的真实值不再改写状态行
                    self.hook_state = Some(r.hook_ready);
                    let (text, kind) = launch_success_text(&r);
                    self.set_status(text, kind);
                    self.persist_settings();
                }
                BgMsg::LaunchDone(Err(e)) => {
                    self.launching = false;
                    self.launch_done_seen = true; // 同上
                    self.hook_state = None;
                    self.set_status(format!("[ERR] 失败：{e}"), StatusKind::Err);
                    self.persist_settings();
                }
            }
        }
    }

    fn do_launch(&mut self, ctx: &egui::Context, mode: Mode) {
        let exe = self.exe_path.trim().to_string();
        if exe.is_empty() {
            self.set_status("[ERR] 请先选择目标程序路径".into(), StatusKind::Err);
            return;
        }
        self.exe_path = exe.clone();
        self.persist_settings();
        self.launching = true;
        self.set_status(
            match mode {
                Mode::Empty => "正在以无值模式注入启动…".into(),
                Mode::Fake => "正在以伪值模式注入启动…".into(),
            },
            StatusKind::Neutral,
        );

        // 启动注入会阻塞最长十几秒（等远程线程装 hook），放到后台线程
        let tx = self.tx.clone();
        let board = self.board.trim().to_string();
        let cpu = self.cpu.trim().to_string();
        let disk = self.disk.trim().to_string();
        let inject_children = self.inject_children;
        let log_enabled = self.log_enabled;
        let ctx = ctx.clone();
        thread::spawn(move || {
            // panic 隔离：保证 LaunchDone 必然回传、launching 必然复位（release 保留 unwind，守卫全程生效）
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::core::launch(
                    exe,
                    match mode {
                        Mode::Empty => Some("empty".to_string()),
                        Mode::Fake => None,
                    },
                    (!board.is_empty()).then_some(board),
                    (!cpu.is_empty()).then_some(cpu),
                    (!disk.is_empty()).then_some(disk),
                    inject_children,
                    log_enabled,
                )
            }))
            .unwrap_or_else(|_| Err("后台线程异常退出（panic）".to_string()));
            let _ = tx.send(BgMsg::LaunchDone(result));
            ctx.request_repaint();
        });
    }

    fn show(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        // eframe 提供的 Ui 不再经过 CentralPanel，自己铺满基板色
        ui.painter().rect_filled(ui.max_rect(), 0.0, BG);
        {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Frame::new()
                        .inner_margin(Margin {
                            left: 28,
                            right: 28,
                            top: 22,
                            bottom: 18,
                        })
                        .show(ui, |ui| {
                            header(ui);
                            ui.add_space(22.0);

                            // ---- 目标程序 ----
                            eyebrow(ui, "目标程序", "TARGET PROCESS");
                            card(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let edit_w =
                                        ui.available_width() - ui.spacing().interact_size.x - 10.0;
                                    ui.add_enabled(
                                        !self.launching,
                                        egui::TextEdit::singleline(&mut self.exe_path)
                                            .hint_text(r"C:\path\to\target.exe")
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(edit_w),
                                    );
                                    if ui
                                        .add_enabled(!self.launching, egui::Button::new("浏览…"))
                                        .clicked()
                                    {
                                        if let Some(p) = rfd::FileDialog::new()
                                            .add_filter("可执行文件", &["exe"])
                                            .pick_file()
                                        {
                                            self.exe_path = p.display().to_string();
                                            self.persist_settings();
                                        }
                                    }
                                });
                                // 设置文件写入失败（如目录只读）时提示一次，写成功后消失
                                if let Some(e) = &self.settings_err {
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new(format!("设置保存失败：{e}"))
                                            .size(12.0)
                                            .color(ERR),
                                    );
                                }
                            });
                            ui.add_space(18.0);

                            // ---- 指纹覆写 ----
                            eyebrow(ui, "指纹覆写", "FINGERPRINT OVERRIDE");
                            card(ui, |ui| {
                                // 模式段选：伪值 = 按输入覆写；无值 = 三类返回 0 实例
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("预填为本机真实值，改成其他机器的值即可伪装")
                                            .size(12.0)
                                            .color(MUTED),
                                    );
                                    ui.with_layout(
                                        Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            let m_empty = ui.selectable_label(
                                                self.mode == Mode::Empty,
                                                "无值启动",
                                            );
                                            let m_fake = ui.selectable_label(
                                                self.mode == Mode::Fake,
                                                "伪值启动",
                                            );
                                            if m_empty.clicked() {
                                                self.mode = Mode::Empty;
                                            }
                                            if m_fake.clicked() {
                                                self.mode = Mode::Fake;
                                            }
                                        },
                                    );
                                });
                                ui.add_space(4.0);

                                let editable = !self.launching && self.mode == Mode::Fake;
                                // 记录用户手动编辑，晚到的真实值不再回填这些字段
                                if fingerprint_field(
                                    ui,
                                    "主板序列号",
                                    "Win32_BaseBoard.SerialNumber",
                                    &mut self.board,
                                    editable,
                                ) {
                                    self.edited[0] = true;
                                }
                                if fingerprint_field(
                                    ui,
                                    "CPU 标识",
                                    "Win32_Processor.ProcessorId",
                                    &mut self.cpu,
                                    editable,
                                ) {
                                    self.edited[1] = true;
                                }
                                if fingerprint_field(
                                    ui,
                                    "磁盘序列号（默认取第一块固定硬盘）",
                                    "Win32_DiskDrive.SerialNumber",
                                    &mut self.disk,
                                    editable,
                                ) {
                                    self.edited[2] = true;
                                }

                                if self.mode == Mode::Empty {
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new(
                                            "无值模式不写入指纹值：三类 WMI 查询返回 0 实例，\
                                             目标程序将走自身的无值回退逻辑。",
                                        )
                                        .size(12.0)
                                        .color(COPPER_HI),
                                    );
                                }

                                // ---- 注入选项 ----
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    if ui
                                        .add_enabled(
                                            !self.launching,
                                            egui::Checkbox::new(
                                                &mut self.inject_children,
                                                RichText::new("子进程传播（onefile 兼容）")
                                                    .size(12.0)
                                                    .color(MUTED),
                                            ),
                                        )
                                        .on_hover_text(
                                            "向目标进程创建的子进程传播注入。\
                                             PyInstaller onefile 目标必须开启；\
                                             若目标对 CreateProcessW 敏感可尝试关闭。",
                                        )
                                        .changed()
                                    {
                                        self.persist_settings();
                                    }
                                    if ui
                                        .add_enabled(
                                            !self.launching,
                                            egui::Checkbox::new(
                                                &mut self.log_enabled,
                                                RichText::new("写运行日志").size(12.0).color(MUTED),
                                            ),
                                        )
                                        .on_hover_text(
                                            "DLL 在自身目录写 wmi-spoofer.log 记录配置与拦截过程；\
                                             不想留运行痕迹可关闭。",
                                        )
                                        .changed()
                                    {
                                        self.persist_settings();
                                    }
                                });
                            });
                            ui.add_space(18.0);

                            // ---- 注入启动 ----
                            let label = if self.launching {
                                "注入中…"
                            } else {
                                match self.mode {
                                    Mode::Fake => "注入启动 · 伪值",
                                    Mode::Empty => "注入启动 · 无值",
                                }
                            };
                            let w = ui.available_width();
                            if ui
                                .add_enabled(
                                    !self.launching,
                                    egui::Button::new(
                                        RichText::new(label).size(15.0).strong().color(BG),
                                    )
                                    .fill(COPPER)
                                    .min_size(vec2(w, 40.0)),
                                )
                                .clicked()
                            {
                                self.do_launch(ui.ctx(), self.mode);
                            }
                            if self.launching {
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label(
                                        RichText::new("正在写入配置并注入，等待远程线程装好 hook…")
                                            .size(12.0)
                                            .color(MUTED),
                                    );
                                });
                                // 注入期间持续重绘，让 spinner 转起来
                                ctx.request_repaint_after(Duration::from_millis(120));
                            }
                            ui.add_space(18.0);

                            // ---- 运行状态 ----
                            eyebrow(ui, "运行状态", "STATUS");
                            card(ui, |ui| {
                                // 头部：状态灯
                                ui.horizontal(|ui| {
                                    let (_, dot) =
                                        ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                                    let dot_color = if self.launching {
                                        // 忙碌时铜灯呼吸
                                        let t = ui.input(|i| i.time) as f32;
                                        let a = 0.45 + 0.55 * (0.5 + 0.5 * (t * 4.0).sin());
                                        COPPER.gamma_multiply(a)
                                    } else {
                                        match self.status_kind {
                                            StatusKind::Neutral => TRACE,
                                            StatusKind::Ok => OK,
                                            StatusKind::Err => ERR,
                                        }
                                    };
                                    ui.painter_at(dot.rect).circle_filled(
                                        dot.rect.center(),
                                        4.0,
                                        dot_color,
                                    );
                                    ui.label(
                                        RichText::new(if self.launching {
                                            "注入中"
                                        } else {
                                            "待命"
                                        })
                                        .size(11.5)
                                        .color(MUTED),
                                    );
                                    ui.with_layout(
                                        Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new("wmi-spoofer.log")
                                                    .size(10.5)
                                                    .monospace()
                                                    .color(MUTED),
                                            );
                                            // hook 就绪状态小片：常驻头部行，不受下方控制台滚动影响
                                            if !self.launching {
                                                if let Some(ready) = self.hook_state {
                                                    hook_chip(ui, ready);
                                                }
                                            }
                                        },
                                    );
                                });
                                ui.add_space(6.0);
                                let text_color = match self.status_kind {
                                    StatusKind::Neutral => TEXT,
                                    StatusKind::Ok => OK,
                                    StatusKind::Err => ERR,
                                };
                                egui::Frame::new()
                                    .fill(WELL)
                                    .corner_radius(6.0)
                                    .inner_margin(Margin::same(10))
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .max_height(120.0)
                                            .stick_to_bottom(true)
                                            .show(ui, |ui| {
                                                ui.set_min_width(ui.available_width());
                                                ui.label(
                                                    RichText::new(&self.status)
                                                        .monospace()
                                                        .size(12.0)
                                                        .color(text_color),
                                                );
                                            });
                                    });
                            });
                        });
                });
        }
    }
}

// ---- 视觉组件 ----

/// 页头：指纹螺纹印 + 眉标 + 标题（文字相对 64px 螺纹印纵向居中）
fn header(ui: &mut Ui) {
    const MARK: f32 = 64.0; // 螺纹印尺寸（决定行高）
    const GAP: f32 = 16.0;

    // 预排版两行文字：颜色直接烘焙进 galley，绕开嵌套布局的间距歧义
    let p = ui.painter().clone();
    let eyebrow = p.layout_no_wrap("WMI SPOOFER".into(), egui::FontId::monospace(11.0), COPPER);
    let title = p.layout_no_wrap("WMI 伪装器".into(), egui::FontId::proportional(22.0), TEXT);

    let spacing = ui.spacing().item_spacing.y;
    let eyebrow_h = eyebrow.size().y;
    let title_h = title.size().y;
    let text_h = eyebrow_h + spacing + title_h;

    // 整块按螺纹印高度分配：左侧画螺纹印，文字右移并纵向居中
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), MARK), Sense::hover());
    fingerprint_mark(
        ui,
        egui::Rect::from_min_size(rect.left_top(), vec2(MARK, MARK)),
        COPPER.gamma_multiply(0.5),
    );
    let top = ((MARK - text_h) * 0.5).max(0.0);
    let x = rect.left() + MARK + GAP;
    p.galley(pos2(x, rect.top() + top), eyebrow, TEXT);
    p.galley(pos2(x, rect.top() + top + eyebrow_h + spacing), title, TEXT);
}

/// 区块眉标：铜色刻线 + 中文标题 + 右侧英文注记
fn eyebrow(ui: &mut Ui, zh: &str, en: &str) {
    ui.horizontal(|ui| {
        let (_, tick) = ui.allocate_exact_size(vec2(4.0, 14.0), Sense::hover());
        ui.painter_at(tick.rect).rect_filled(tick.rect, 2.0, COPPER);
        ui.add_space(4.0);
        ui.label(RichText::new(zh).size(13.5).color(TEXT));
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(en).monospace().size(10.5).color(MUTED));
        });
    });
    ui.add_space(6.0);
}

/// 卡片容器
fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(PANEL)
        .corner_radius(CornerRadius::same(8))
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| add(ui))
        .inner
}

/// 单个指纹字段：名称 + 状态小片（覆写/真实） + 右侧 WMI 类路径 + 等宽输入井。
/// 返回本次帧用户是否修改了内容（用于阻止晚到的真实值回填）
fn fingerprint_field(
    ui: &mut Ui,
    name: &str,
    class_path: &str,
    val: &mut String,
    editable: bool,
) -> bool {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(name).size(13.0).color(TEXT));
        ui.add_space(4.0);
        let overridden = !val.trim().is_empty();
        chip(ui, if overridden { "覆写" } else { "真实" }, overridden);
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(class_path)
                    .monospace()
                    .size(11.0)
                    .color(MUTED),
            );
        });
    });
    ui.add_space(3.0);
    let resp = ui.add_enabled(
        editable,
        egui::TextEdit::singleline(val)
            .hint_text("（留空 = 使用真实值）")
            .font(egui::TextStyle::Monospace)
            .desired_width(ui.available_width()),
    );
    resp.changed()
}

/// 状态小片：覆写（铜）/ 真实（灰绿）
fn chip(ui: &mut Ui, text: &str, hot: bool) {
    let (bg, fg) = if hot {
        (COPPER.gamma_multiply(0.22), COPPER_HI)
    } else {
        (TRACE.gamma_multiply(0.55), MUTED)
    };
    Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.5).color(fg));
        });
}

/// hook 就绪状态小片（状态行常驻展示）：绿 = 已确认，橙红 = 未确认
fn hook_chip(ui: &mut Ui, ready: bool) {
    let (bg, fg, text) = if ready {
        (OK.gamma_multiply(0.18), OK, "hook 已确认生效")
    } else {
        (ERR.gamma_multiply(0.18), ERR, "hook 未确认生效")
    };
    let resp = Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(10.5).color(fg));
        })
        .response;
    resp.on_hover_text(if ready {
        "DLL 已通过就绪事件确认全部 hook 启用"
    } else {
        "等待就绪事件超时：hook 安装可能仍在进行或已失败，详见 wmi-spoofer.log。\
         若日志里的成功行是旧文案（hook 安装成功：…），说明部署目录的 DLL 是旧版，需用新构建的 DLL 替换"
    });
}

/// 指纹螺纹印：5 圈同心断弧，缺口角度随圈错开
fn fingerprint_mark(ui: &mut Ui, rect: egui::Rect, color: Color32) {
    let p = ui.painter_at(rect);
    let c = rect.center();
    const SEGMENTS: [(f32, f32); 3] = [(0.4, 2.3), (2.7, 4.6), (5.05, 6.1)];
    for ring in 1..=5u32 {
        let r = ring as f32 * 5.2 + 2.0;
        let offset = ring as f32 * 0.9;
        for (a0, a1) in SEGMENTS {
            let n = 14;
            let pts: Vec<Pos2> = (0..=n)
                .map(|i| {
                    let t = a0 + (a1 - a0) * (i as f32 / n as f32) + offset;
                    pos2(c.x + r * t.cos(), c.y + r * t.sin())
                })
                .collect();
            p.add(Shape::line(pts, Stroke::new(1.3, color)));
        }
    }
    p.circle_filled(c, 1.6, color);
}

/// 启动成功的状态文案（无值启动与伪值启动不同；hook 状态由状态行的小片常驻展示）
fn launch_success_text(r: &LaunchResult) -> (String, StatusKind) {
    if r.deny {
        let text = format!(
            "[OK] 无值启动成功  PID = {}\n\
             \n\
             已向目标进程下发 EMPTY 参数（WMI_SPOOFER_EMPTY=board,cpu,disk）：\n\
             \x20 Win32_Processor / Win32_BaseBoard / Win32_DiskDrive\n\
             \x20 三类查询返回 0 实例，目标程序读不到任何指纹，\n\
             \x20 将走其自身的无值回退逻辑。",
            r.pid,
        );
        return (text, StatusKind::Ok);
    }

    let none = "（未覆盖，真实值）";
    let text = format!(
        "[OK] 伪值启动成功  PID = {}\n\
         \n\
         已向目标进程下发假值（环境变量）：\n\
         \x20 Win32_BaseBoard.SerialNumber = {}\n\
         \x20 Win32_Processor.ProcessorId  = {}\n\
         \x20 Win32_DiskDrive.SerialNumber = {}\n\
         \n\
         打开启动器同目录下 wmi-spoofer.log 可查看生效配置与拦截记录。",
        r.pid,
        r.board_serial.as_deref().unwrap_or(none),
        r.processor_id.as_deref().unwrap_or(none),
        r.disk_serial.as_deref().unwrap_or(none),
    );
    (text, StatusKind::Ok)
}

impl eframe::App for LauncherApp {
    // eframe 0.37：直接拿到整窗 Ui（取代旧版 update + CentralPanel）
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_messages();
        self.show(ui, &ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_settings_reads_keys_and_keeps_defaults() {
        let s = parse_settings("[Settings]\r\nexe_path=C:\\a b\\t.exe\r\ninject_children=0\r\n");
        assert_eq!(s.exe_path, r"C:\a b\t.exe");
        assert!(!s.inject_children);
        // 缺省键沿用默认值（开）
        assert!(s.log_enabled);
    }

    #[test]
    fn parse_settings_missing_keys_yields_defaults() {
        let s = parse_settings("");
        assert!(s.exe_path.is_empty());
        assert!(s.inject_children && s.log_enabled);
    }

    // ---- 后台消息不得覆盖较新的用户输入 / 启动状态 ----

    /// 直接构造 LauncherApp（不经过需要 eframe CreationContext 的 new）
    fn make_app(rx: Receiver<BgMsg>) -> LauncherApp {
        let (tx, _drop) = mpsc::channel();
        LauncherApp {
            tx,
            rx,
            exe_path: String::new(),
            board: String::new(),
            cpu: String::new(),
            disk: String::new(),
            mode: Mode::Fake,
            inject_children: true,
            log_enabled: true,
            status: String::new(),
            status_kind: StatusKind::Neutral,
            launching: false,
            settings_err: None,
            hook_state: None,
            edited: [false; 3],
            launch_done_seen: false,
        }
    }

    fn real_values_msg() -> BgMsg {
        BgMsg::RealValues(Ok(RealValues {
            board_serial: "REALBOARD".into(),
            processor_id: "REALCPU".into(),
            disk_serial: "REALDISK".into(),
        }))
    }

    fn launch_done_msg() -> BgMsg {
        BgMsg::LaunchDone(Ok(crate::core::LaunchResult {
            pid: 42,
            deny: false,
            hook_ready: true,
            board_serial: None,
            processor_id: None,
            disk_serial: None,
        }))
    }

    #[test]
    fn real_values_skips_user_edited_fields() {
        let (tx, rx) = mpsc::channel();
        let mut app = make_app(rx);
        app.board = "用户已填".into();
        app.edited = [true, false, false]; // 仅主板被用户编辑
        tx.send(real_values_msg()).unwrap();
        app.drain_messages();
        assert_eq!(app.board, "用户已填", "编辑过的字段不得被回填覆盖");
        assert_eq!(app.cpu, "REALCPU");
        assert_eq!(app.disk, "REALDISK");
    }

    #[test]
    fn late_real_values_does_not_overwrite_launch_status() {
        let (tx, rx) = mpsc::channel();
        let mut app = make_app(rx);
        tx.send(launch_done_msg()).unwrap();
        app.drain_messages();
        let status_after_launch = app.status.clone();
        tx.send(real_values_msg()).unwrap();
        app.drain_messages();
        assert!(app.launch_done_seen);
        assert_eq!(
            app.status, status_after_launch,
            "晚到的真实值不得改写启动状态行"
        );
    }

    /// 晚到的 RealValues(Err) 与 Ok 分支同口径——不得覆盖启动状态行；
    /// 启动前到达的读取失败仍然可见（门控只拦晚到消息）。
    #[test]
    fn late_real_values_err_does_not_overwrite_launch_status() {
        let (tx, rx) = mpsc::channel();
        let mut app = make_app(rx);
        tx.send(launch_done_msg()).unwrap();
        app.drain_messages();
        let status_after_launch = app.status.clone();

        tx.send(BgMsg::RealValues(Err("COM 初始化失败".into())))
            .unwrap();
        app.drain_messages();
        assert_eq!(
            app.status, status_after_launch,
            "晚到的真实值读取失败不得改写启动状态行"
        );

        // 对照：未启动过的应用收到读取失败，状态行应当出现警告
        let (tx2, rx2) = mpsc::channel();
        let mut fresh = make_app(rx2);
        tx2.send(BgMsg::RealValues(Err("COM 初始化失败".into())))
            .unwrap();
        fresh.drain_messages();
        assert!(
            fresh.status.contains("自动读取本机真实值失败"),
            "启动前的读取失败应当可见，实际状态行：{}",
            fresh.status
        );
    }

    #[test]
    fn real_values_before_launch_fills_and_launch_overwrites() {
        let (tx, rx) = mpsc::channel();
        let mut app = make_app(rx);
        tx.send(real_values_msg()).unwrap();
        app.drain_messages();
        assert_eq!(app.board, "REALBOARD");
        assert_eq!(app.cpu, "REALCPU");
        assert_eq!(app.disk, "REALDISK");
        tx.send(launch_done_msg()).unwrap();
        app.drain_messages();
        assert!(app.hook_state == Some(true));
        assert_ne!(app.status, "等待操作 — 选择目标程序后注入启动。");
    }
}
