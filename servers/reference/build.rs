//! Embute o icone da marca no .exe do Windows.
fn main() {
    println!("cargo:rerun-if-changed=../../assets/brand/openvnc.rc");
    println!("cargo:rerun-if-changed=../../assets/brand/openvnc.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("../../assets/brand/openvnc.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("recurso do icone");
    }
}
