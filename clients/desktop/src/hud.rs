//! Controles para celular no estilo do RDP: a imagem remota ocupa a tela
//! toda e fica so um botao flutuante, que o usuario arrasta para onde
//! quiser. Um toque nele abre o menu com teclado, mouse, arquivos, abas e
//! o resto.

use eframe::egui;

use crate::transfer;

/// Campos da aba e do app que o menu altera.
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
    /// Rotulos das abas abertas e se cada uma esta conectada.
    pub tabs: Vec<(String, bool)>,
    pub active: usize,
    /// Aba escolhida no menu (troca de conexao).
    pub switch_to: &'a mut Option<usize>,
    /// Abrir a tela de nova conexao.
    pub new_conn: &'a mut bool,
    /// Pedido de trocar o monitor remoto, se o servidor tiver mais de um.
    pub next_screen: Option<&'a mut bool>,
}

/// Desenha o botao flutuante e, se aberto, o menu.
pub fn show(ctx: &egui::Context, h: Hud<'_>) {
    let id = egui::Id::new("openvnc_fab");
    let mut open: bool = ctx.data(|d| d.get_temp(id.with("open"))).unwrap_or(false);
    let screen = ctx.screen_rect();
    // Area movel: arrastar move, toque abre. A posicao fica na memoria do egui
    let fab = egui::Area::new(id)
        .movable(true)
        .constrain(true)
        .default_pos(egui::pos2(screen.right() - 64.0, screen.center().y))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            let dot = if h.encrypted {
                egui::Color32::from_rgb(80, 180, 80)
            } else {
                egui::Color32::from_rgb(220, 160, 0)
            };
            let b = egui::Button::new(egui::RichText::new("\u{2630}").size(22.0).color(dot))
                .fill(egui::Color32::from_black_alpha(150))
                .corner_radius(24.0)
                .min_size(egui::vec2(48.0, 48.0));
            ui.add(b).on_hover_text("Menu (arraste para mover)")
        });
    if fab.inner.clicked() {
        open = !open;
    }
    if open {
        let anchor = fab.response.rect;
        // abre para o lado com mais espaco
        let left = anchor.center().x > screen.center().x;
        let up = anchor.center().y > screen.center().y;
        let pivot = match (left, up) {
            (true, true) => egui::Align2::RIGHT_BOTTOM,
            (true, false) => egui::Align2::RIGHT_TOP,
            (false, true) => egui::Align2::LEFT_BOTTOM,
            (false, false) => egui::Align2::LEFT_TOP,
        };
        let at = egui::pos2(
            if left {
                anchor.left() - 6.0
            } else {
                anchor.right() + 6.0
            },
            if up { anchor.bottom() } else { anchor.top() },
        );
        let menu = egui::Area::new(id.with("menu"))
            .order(egui::Order::Foreground)
            .pivot(pivot)
            .fixed_pos(at)
            .constrain(true)
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style()).show(ui, |ui| {
                    ui.set_max_width(240.0);
                    ui.label(egui::RichText::new(h.title).strong());
                    ui.label(egui::RichText::new(h.status).small().weak());
                    ui.separator();
                    let mut close = false;
                    if ui.toggle_value(h.osk, "Teclado").clicked() {
                        close = true;
                    }
                    ui.toggle_value(h.touchpad, "Mouse virtual");
                    ui.checkbox(h.fit, "Ajustar a tela");
                    if let Some(ns) = h.next_screen {
                        if ui.button("Trocar tela").clicked() {
                            *ns = true;
                            close = true;
                        }
                    }
                    if h.files.is_some() {
                        if ui.toggle_value(h.show_explorer, "Arquivos").clicked() {
                            close = true;
                        }
                        ui.checkbox(h.show_files, "Envio rapido de arquivos");
                    }
                    if let Some(link) = h.files {
                        crate::explorer::lock_toggle(ui, link, false);
                    }
                    ui.separator();
                    if h.tabs.len() > 1 {
                        ui.label(egui::RichText::new("Conexoes").small().weak());
                        for (i, (label, up)) in h.tabs.iter().enumerate() {
                            let mark = if *up { "\u{25CF} " } else { "\u{25CB} " };
                            if ui
                                .selectable_label(i == h.active, format!("{mark}{label}"))
                                .clicked()
                            {
                                *h.switch_to = Some(i);
                                close = true;
                            }
                        }
                    }
                    if ui.button("Nova conexao").clicked() {
                        *h.new_conn = true;
                        close = true;
                    }
                    if ui.button("Desconectar").clicked() {
                        *h.disconnect = true;
                        close = true;
                    }
                    if close {
                        open = false;
                    }
                });
            });
        // toque fora do menu e do botao fecha
        let outside = ctx.input(|i| i.pointer.any_pressed())
            && !menu.response.contains_pointer()
            && !fab.response.contains_pointer()
            && !ctx.memory(|m| m.any_popup_open());
        if outside {
            open = false;
        }
    }
    ctx.data_mut(|d| d.insert_temp(id.with("open"), open));
}
