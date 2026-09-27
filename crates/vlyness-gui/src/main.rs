//! VLYNESS GUI-клиент для Windows (eframe).
//!
//! Тонкая оболочка над [`vlyness_cli::client::Controller`]: кнопка подключения,
//! состояние линка, счётчики трафика, импорт профилей (файл/вставка/drag-drop), адрес
//! SOCKS5, лог и автозапуск. Вся сетевая логика — в библиотеке клиента; здесь только UI.

// На Windows не открывать консольное окно рядом с GUI.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use eframe::egui;
use serde::{Deserialize, Serialize};

use vlyness_cli::client::{load_profile, parse_profile, Controller, LinkState, StatusSnapshot};
use vlyness_profile::Profile;

fn main() -> eframe::Result<()> {
    let autostart = std::env::args().any(|a| a == "--autostart");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 660.0])
            .with_min_inner_size([440.0, 520.0])
            .with_title("VLYNESS"),
        ..Default::default()
    };
    eframe::run_native(
        "VLYNESS",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, autostart)))),
    )
}

// ───────────────────────── Настройки (персистентные) ─────────────────────────

#[derive(Serialize, Deserialize)]
struct Settings {
    profile_paths: Vec<String>,
    socks_bind: String,
    reference: String,
    autostart: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            profile_paths: Vec::new(),
            socks_bind: "127.0.0.1:1080".to_string(),
            reference: String::new(),
            autostart: false,
        }
    }
}

/// Каталог настроек: `%APPDATA%\VLYNESS` на Windows, иначе рядом с текущим каталогом.
fn config_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("VLYNESS")
}

fn settings_path() -> PathBuf {
    config_dir().join("gui.json")
}

fn profiles_dir() -> PathBuf {
    config_dir().join("profiles")
}

fn load_settings() -> Settings {
    match std::fs::read_to_string(settings_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

fn save_settings(s: &Settings) {
    let _ = std::fs::create_dir_all(config_dir());
    if let Ok(json) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(settings_path(), json);
    }
}

// ───────────────────────── Автозапуск (Windows) ─────────────────────────

#[cfg(windows)]
fn set_autostart(enable: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy().to_string();
    let out = if enable {
        std::process::Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "VLYNESS",
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{exe}\" --autostart"),
                "/f",
            ])
            .output()
    } else {
        std::process::Command::new("reg")
            .args([
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "VLYNESS",
                "/f",
            ])
            .output()
    };
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(not(windows))]
fn set_autostart(_enable: bool) -> Result<(), String> {
    Err("автозапуск поддержан только на Windows".to_string())
}

// ───────────────────────── Приложение ─────────────────────────

struct App {
    settings: Settings,
    /// Загруженные профили: `(путь, профиль)`.
    profiles: Vec<(String, Profile)>,
    load_errors: Vec<String>,
    paste_buf: String,
    controller: Option<Controller>,
    status: StatusSnapshot,
    log_since: u64,
    log: Vec<String>,
    ui_error: Option<String>,
}

fn idle_status() -> StatusSnapshot {
    StatusSnapshot {
        state: LinkState::Idle,
        carrier_id: String::new(),
        mode: String::new(),
        socks_addr: String::new(),
        bytes_up: 0,
        bytes_down: 0,
        last_error: None,
    }
}

impl App {
    fn new(_cc: &eframe::CreationContext<'_>, autostart: bool) -> Self {
        let settings = load_settings();
        let mut app = App {
            settings,
            profiles: Vec::new(),
            load_errors: Vec::new(),
            paste_buf: String::new(),
            controller: None,
            status: idle_status(),
            log_since: 0,
            log: Vec::new(),
            ui_error: None,
        };
        // Загрузить ранее сохранённые профили.
        let paths = app.settings.profile_paths.clone();
        for p in paths {
            app.try_add_path(&p, false);
        }
        // Автозапуск: если запущены с --autostart и есть профили — подключиться сразу.
        if autostart && !app.profiles.is_empty() {
            app.connect();
        }
        app
    }

    fn persist(&mut self) {
        self.settings.profile_paths = self.profiles.iter().map(|(p, _)| p.clone()).collect();
        save_settings(&self.settings);
    }

    /// Загрузить профиль из файла; `persist` — сохранить список после добавления.
    fn try_add_path(&mut self, path: &str, persist: bool) {
        if self.profiles.iter().any(|(p, _)| p == path) {
            return;
        }
        match load_profile(path) {
            Ok(pr) => {
                self.profiles.push((path.to_string(), pr));
                if persist {
                    self.persist();
                }
            }
            Err(e) => self.load_errors.push(e),
        }
    }

    /// Разобрать профиль из вставленного JSON, сохранить в каталог профилей и добавить.
    fn add_from_paste(&mut self) {
        let text = self.paste_buf.trim().to_string();
        if text.is_empty() {
            return;
        }
        match parse_profile(&text) {
            Ok(pr) => {
                let dir = profiles_dir();
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    self.ui_error = Some(format!("не удалось создать каталог профилей: {e}"));
                    return;
                }
                let path = dir.join(format!("{}.json", sanitize(&pr.id)));
                if let Err(e) = std::fs::write(&path, pr.to_json()) {
                    self.ui_error = Some(format!("не удалось сохранить профиль: {e}"));
                    return;
                }
                let path = path.to_string_lossy().to_string();
                if !self.profiles.iter().any(|(p, _)| p == &path) {
                    self.profiles.push((path, pr));
                    self.persist();
                }
                self.paste_buf.clear();
            }
            Err(e) => self.ui_error = Some(e),
        }
    }

    fn connect(&mut self) {
        if self.controller.is_some() {
            return;
        }
        if self.profiles.is_empty() {
            self.ui_error = Some("нет профилей — добавь client.json".to_string());
            return;
        }
        self.ui_error = None;
        self.log.clear();
        self.log_since = 0;
        let profiles: Vec<Profile> = self.profiles.iter().map(|(_, p)| p.clone()).collect();
        let reference = {
            let r = self.settings.reference.trim();
            if r.is_empty() { None } else { Some(r.to_string()) }
        };
        match Controller::start_pool(profiles, self.settings.socks_bind.clone(), reference) {
            Ok(c) => self.controller = Some(c),
            Err(e) => self.ui_error = Some(format!("не удалось запустить: {e}")),
        }
        self.persist();
    }

    fn disconnect(&mut self) {
        if let Some(c) = self.controller.take() {
            c.stop();
        }
        self.status = idle_status();
    }

    fn poll(&mut self) {
        if let Some(c) = &self.controller {
            self.status = c.status();
            let (next, mut lines) = c.logs_since(self.log_since);
            self.log_since = next;
            self.log.append(&mut lines);
            if self.log.len() > 500 {
                let drop = self.log.len() - 500;
                self.log.drain(0..drop);
            }
            // Цикл сам завершился (фатальная ошибка) — снять контроллер.
            if !c.is_running() {
                self.status = c.status();
            }
        }
    }
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

fn state_color(s: LinkState) -> egui::Color32 {
    match s {
        LinkState::Up => egui::Color32::from_rgb(60, 180, 90),
        LinkState::Connecting | LinkState::Switching => egui::Color32::from_rgb(220, 170, 40),
        LinkState::Frozen => egui::Color32::from_rgb(220, 120, 40),
        LinkState::Error => egui::Color32::from_rgb(210, 70, 70),
        LinkState::Idle | LinkState::Stopped => egui::Color32::GRAY,
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Принять перетащенные файлы профилей.
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        for path in dropped {
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(s) = path.to_str() {
                    self.try_add_path(s, true);
                }
            }
        }

        self.poll();
        let connected = self.controller.is_some();

        egui::TopBottomPanel::top("head").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("VLYNESS");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let st = self.status.state;
                    ui.colored_label(state_color(st), format!("● {}", st.label()));
                });
            });
            ui.add_space(6.0);
        });

        egui::TopBottomPanel::bottom("foot").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("↑");
                ui.monospace(human(self.status.bytes_up));
                ui.separator();
                ui.label("↓");
                ui.monospace(human(self.status.bytes_down));
                ui.separator();
                if !self.status.socks_addr.is_empty() {
                    ui.label("SOCKS5:");
                    ui.monospace(&self.status.socks_addr);
                }
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Кнопка подключения.
            ui.horizontal(|ui| {
                if !connected {
                    let enabled = !self.profiles.is_empty();
                    if ui
                        .add_enabled(enabled, egui::Button::new("  Подключить  "))
                        .clicked()
                    {
                        self.connect();
                    }
                } else if ui.button("  Отключить  ").clicked() {
                    self.disconnect();
                }
                if !self.status.carrier_id.is_empty() {
                    ui.label(format!("носитель: {} ({})", self.status.carrier_id, self.status.mode));
                }
            });

            if let Some(e) = &self.status.last_error {
                ui.colored_label(egui::Color32::from_rgb(210, 90, 90), format!("⚠ {e}"));
            }
            if let Some(e) = &self.ui_error {
                ui.colored_label(egui::Color32::from_rgb(210, 90, 90), format!("⚠ {e}"));
            }

            ui.separator();

            // Настройки (редактируемы, когда отключены).
            ui.add_enabled_ui(!connected, |ui| {
                egui::Grid::new("cfg").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                    ui.label("SOCKS5 адрес:");
                    ui.text_edit_singleline(&mut self.settings.socks_bind);
                    ui.end_row();
                    ui.label("Контрольный хост:");
                    let r = ui.text_edit_singleline(&mut self.settings.reference);
                    if r.lost_focus() {
                        self.persist();
                    }
                    ui.end_row();
                });
                let mut autostart = self.settings.autostart;
                if ui.checkbox(&mut autostart, "Запускать при входе в Windows").changed() {
                    match set_autostart(autostart) {
                        Ok(()) => {
                            self.settings.autostart = autostart;
                            self.persist();
                        }
                        Err(e) => self.ui_error = Some(format!("автозапуск: {e}")),
                    }
                }
            });

            ui.separator();

            // Профили.
            ui.horizontal(|ui| {
                ui.label(format!("Профили ({})", self.profiles.len()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!connected, egui::Button::new("Очистить")).clicked() {
                        self.profiles.clear();
                        self.persist();
                    }
                    if ui.add_enabled(!connected, egui::Button::new("Из файла…")).clicked() {
                        if let Some(files) = rfd::FileDialog::new()
                            .add_filter("VLYNESS профиль", &["json"])
                            .pick_files()
                        {
                            for f in files {
                                if let Some(s) = f.to_str() {
                                    self.try_add_path(s, true);
                                }
                            }
                        }
                    }
                });
            });

            egui::ScrollArea::vertical()
                .id_source("profiles")
                .max_height(96.0)
                .show(ui, |ui| {
                    let mut remove: Option<usize> = None;
                    for (i, (path, pr)) in self.profiles.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.add_enabled(!connected, egui::Button::new("✕").small()).clicked() {
                                remove = Some(i);
                            }
                            ui.label(format!("{}  ", pr.id));
                            ui.weak(short_path(path));
                        });
                    }
                    if let Some(i) = remove {
                        self.profiles.remove(i);
                        self.persist();
                    }
                });

            ui.collapsing("Вставить профиль (JSON)", |ui| {
                ui.add_enabled_ui(!connected, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.paste_buf)
                            .desired_rows(4)
                            .hint_text("вставь содержимое client.json…"),
                    );
                    if ui.button("Добавить из буфера").clicked() {
                        self.add_from_paste();
                    }
                });
            });

            if !self.load_errors.is_empty() {
                ui.collapsing("Ошибки загрузки профилей", |ui| {
                    for e in &self.load_errors {
                        ui.colored_label(egui::Color32::from_rgb(200, 120, 120), e);
                    }
                    if ui.button("Скрыть").clicked() {
                        self.load_errors.clear();
                    }
                });
            }

            ui.separator();
            ui.label("Лог:");
            egui::ScrollArea::vertical()
                .id_source("log")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.monospace(line);
                    }
                });
        });

        // Пока подключены — обновляем статус/лог/трафик.
        if connected {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

fn short_path(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}
