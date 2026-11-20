// launcher —— WMI 伪装器（wmi-spoofer，egui / eframe）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod core;
mod inject;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("WMI 伪装器")
            .with_inner_size([780.0, 700.0])
            .with_min_inner_size([680.0, 580.0]),
        ..Default::default()
    };
    eframe::run_native(
        "WMI 伪装器",
        options,
        Box::new(|cc| Ok(Box::new(app::LauncherApp::new(cc)))),
    )
}
