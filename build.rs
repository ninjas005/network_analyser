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
    // Packet capture uses Npcap's wpcap.dll. Delay-load it so the app still
    // starts without Npcap installed (capture::available() checks for it and
    // the capture tab explains how to install it).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
