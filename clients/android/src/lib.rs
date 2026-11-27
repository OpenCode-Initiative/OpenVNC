//! App Android: reaproveita a GUI do cliente desktop (`clients/desktop`)
//! inteira e liga o mouse virtual e o teclado do sistema.

#[allow(dead_code, unused_imports)]
#[path = "../../desktop/src/main.rs"]
mod desktop;
// os modulos do desktop usam `crate::explorer` e `crate::transfer`
#[allow(unused_imports)]
use desktop::{explorer, transfer};

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    // known_hosts e downloads vao para a pasta privada do app
    if let Some(p) = app.internal_data_path() {
        std::env::set_var("HOME", &p);
        std::env::set_var("USERPROFILE", &p);
    }
    let _ = tracing_subscriber::fmt().with_ansi(false).try_init();

    let kb = app.clone();
    let opts = eframe::NativeOptions {
        android_app: Some(app),
        // OpenGL ES funciona em qualquer GPU de celular (e no emulador)
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    let mut shown = false;
    let hook = Box::new(move |ctx: &eframe::egui::Context| {
        let want = desktop::wants_soft_keyboard(ctx);
        if want != shown {
            shown = want;
            if want {
                kb.show_soft_input(true);
            } else {
                kb.hide_soft_input(true);
            }
        }
        // area livre das barras do sistema (pixels) -> faixas em pontos
        let r = kb.content_rect();
        let h = kb.native_window().map(|w| w.height()).unwrap_or(0);
        let ppp = ctx.pixels_per_point().max(0.1);
        let top = r.top.max(0) as f32 / ppp;
        let bottom = if h > 0 && r.bottom > 0 { (h - r.bottom).max(0) as f32 / ppp } else { 0.0 };
        (top, bottom)
    });
    if let Err(e) = desktop::run_mobile(opts, hook) {
        tracing::error!("OpenVNC: {e}");
    }
}
