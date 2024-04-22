use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Ok(contents) = fs::read_to_string(".env") {
        // 按行迭代 .env 文件中的内容
        for line in contents.lines() {
            // 解析每行内容并将其分割为键值对
            let parts: Vec<_> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                // 设置环境变量
                env::set_var(parts[0], parts[1]);
            }
        }
    }
    let pcap_root=env::var("PCAP_ROOT").unwrap();
    let sys_time_root=env::var("SYS_TIME_ROOT").unwrap();
    println!(
        "cargo:rustc-link-search={}\\Lib\\x64",
        pcap_root
    );
    println!("cargo:rustc-link-lib=wpcap");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}\\Include",pcap_root))
        .clang_arg(format!("-I{}",sys_time_root))
        // The input header we would like to generate
        // bindings for.
        .header("pcap.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pcap.rs"))
        .expect("Couldn't write bindings!");
}
