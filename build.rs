fn main() {
    // Embed the application icon and version info into the Windows .exe.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "Network Analyser")
            .set("FileDescription", "Network Analyser - LAN scanner");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed Windows icon: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
