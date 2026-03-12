use libbpf_cargo::SkeletonBuilder;
use std::{env, fs, path::PathBuf, process::Command};

const SRC: &str = "src/bpf/filter.bpf.c";
const SHARED_HEADER: &str = "src/bpf/shared.h";

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    // Get the stable target directory (not profile-specific OUT_DIR)
    let target_dir = get_target_dir();

    // Create a stable subdirectory for generated BPF headers in target/
    let bpf_headers_dir = target_dir.join("bpf_headers");
    fs::create_dir_all(&bpf_headers_dir).expect("Failed to create bpf_headers directory");

    // Generate vmlinux.h in the stable location
    let vmlinux_path = bpf_headers_dir.join("vmlinux.h");

    if !vmlinux_path.exists() {
        let status = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to execute bpftool - ensure it's installed");

        if !status.status.success() {
            panic!(
                "bpftool failed: {}",
                String::from_utf8_lossy(&status.stderr)
            );
        }

        fs::write(&vmlinux_path, status.stdout).expect("Failed to write vmlinux.h");

        println!("Generated vmlinux.h at {:?}", vmlinux_path);
    } else {
        println!("Using existing vmlinux.h at {:?}", vmlinux_path);
    }

    let extra_clang_args = vec![
        // generated vmlinux.h is incompatible with C23 native bool as of 2026 :(
        "-std=gnu17",
        "-Wno-c23-extensions",
        "-I",
        bpf_headers_dir.to_str().unwrap(),
        "-mcpu=v3",
    ];
    generate_compile_commands(&extra_clang_args);
    generate_bindings(&bpf_headers_dir, &out_dir);

    // Build the BPF skeleton
    let mut skel_path = out_dir.clone();
    skel_path.push("filter.skel.rs");

    println!(
        "cargo:rustc-env=LIBBPF_RS_SKEL_PATH={}",
        skel_path.display()
    );

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(&extra_clang_args)
        .build_and_generate(&skel_path)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed={}", SHARED_HEADER);
}

fn get_target_dir() -> PathBuf {
    // Try CARGO_TARGET_DIR first (if user has set it)
    if let Ok(target) = env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target);
    }

    // Otherwise, derive from CARGO_MANIFEST_DIR
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir).join("target")
}

fn generate_compile_commands(extra_clang_args: &Vec<&str>) {
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let src_file = PathBuf::from(&project_root).join(SRC);

    let compile_commands_path = PathBuf::from(&project_root)
        .join("target")
        .join("compile_commands.json");

    let mut args = vec!["clang", "-target", "bpf", "-g", "-O2"];
    args.extend(extra_clang_args.iter().cloned());
    args.extend(["-c", src_file.to_str().unwrap()]);
    // Build the clang command that matches what libbpf-cargo uses
    let compile_command = serde_json::json!([
        {
            "directory": project_root,
            "file": src_file,
            "arguments": args,
        }
    ]);

    fs::write(
        &compile_commands_path,
        serde_json::to_string_pretty(&compile_command).unwrap(),
    )
    .expect("Failed to write compile_commands.json");

    println!(
        "Generated compile_commands.json at {:?}",
        compile_commands_path
    );
}

fn generate_bindings(bpf_headers_dir: &PathBuf, out_dir: &PathBuf) {
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let header_path = PathBuf::from(&project_root).join(SHARED_HEADER);
    let bindings_path = out_dir.join("bindings.rs");

    println!("Generating Rust bindings from {:?}", header_path);

    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .clang_args(["-target", "bpf"])
        // Add the bpf_headers directory to the include path
        .clang_arg(format!("-I{}", bpf_headers_dir.to_str().unwrap()))
        // Derive useful traits
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_partialeq(true)
        // Generate bindings for the types we care about
        .allowlist_type("Syscall")
        .rustified_enum("Syscall")
        .allowlist_type("Event")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!("Generated Rust bindings at {:?}", bindings_path);
}
