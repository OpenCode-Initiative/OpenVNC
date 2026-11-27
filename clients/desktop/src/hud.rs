//! Barra compacta para celular: uma linha fina de icones, menu "mais" com
//! o resto, e auto-ocultar com uma alca flutuante pequena, deixando a
//! imagem remota com a tela quase toda.

use eframe::egui;

use crate::transfer;

/// Sem toque na barra por este tempo, ela se recolhe.
const AUTO_HIDE_SECS: f64 = 4.0;

/// Campos da aba e do app que a barra altera.
pub struct Hud<'a> {
    pub disconnect: &'a mut bool,
    pub fit: &'a mut bool,
    pub touchpad: &'a mut bool,
    pub osk: &'a mut bool,
    pub show_files: &'a mut bool,
    pub show_explorer: &'a mut bool,
    pub files: Option<&'a transfer::FileLink>,
    pub title: &'a str,
    pub status: &'a str,
    pub encrypted: bool,
}

#[derive(Clone, Copy, Default)]
struct State {
    hidden: bool,
    last: f64,
}

/// Desenha a barra (ou a alca, se recolhida).
pub fn show(ctx: &egui::Context, h: Hud<'_>) {
    let id = egui::Id::new("openvnc_hud");
    let now = ctx.input(|i| i.time);
    let mut st: State = ctx.data(|d| d.get_temp(id)).unwrap_or(State {
        hidden: false,
        last: now,
    });
    if st.hidden {
        // alca: botao pequeno no topo, semitransparente
        egui::Area::new(id.with("alca"))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 2.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                let b = egui::Button::new(egui::RichText::new("  v  ").small())
                    .fill(egui::Color32::from_black_alpha(140));
                if ui.add(b).on_hover_text("Mostrar a barra").clicked() {
                    st = State {
                        hidden: false,
                        last: now,
                    };
                }
            });
    } else {
        let r = egui::TopBottomPanel::top("hud")
            .exact_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    if ui.button("X").on_hover_text("Desconectar").clicked() {
                        *h.disconnect = true;
                    }
                    ui.toggle_value(h.osk, "Tecl").on_hover_text("Teclado");
                    ui.toggle_value(h.touchpad, "Mouse")
                        .on_hover_text("Mouse virtual");
                    if h.files.is_some() {
                        ui.toggle_value(h.show_explorer, "Arq")
                            .on_hover_text("Explorador de arquivos");
                    }
                    let dot = if h.encrypted {
                        egui::Color32::from_rgb(80, 180, 80)
                    } else {
                        egui::Color32::from_rgb(220, 160, 0)
                    };
                    ui.colored_label(dot, "*").on_hover_text(if h.encrypted {
                        "TLS"
                    } else {
                        "sem criptografia"
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("^").on_hover_text("Recolher a barra").clicked() {
                            st.hidden = true;
                        }
                        ui.menu_button("...", |ui| {
                            ui.label(egui::RichText::new(h.title).strong());
                            ui.label(egui::RichText::new(h.status).small());
                            ui.separator();
                            ui.checkbox(h.fit, "Ajustar a tela");
                            if h.files.is_some() {
                                ui.checkbox(h.show_files, "Envio rapido de arquivos");
                            }
                            if let Some(link) = h.files {
                                crate::explorer::lock_toggle(ui, link, false);
                            }
                            ui.separator();
                            if ui.button("Desconectar").clicked() {
                                *h.disconnect = true;
                                ui.close_menu();
                            }
                        });
                    });
                });
            });
        let busy = r.response.contains_pointer() || ctx.memory(|m| m.any_popup_open());
        if busy || *h.show_explorer {
            st.last = now;
        } else if now - st.last > AUTO_HIDE_SECS {
            st.hidden = true;
        }
        if !st.hidden {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
    ctx.data_mut(|d| d.insert_temp(id, st));
}
