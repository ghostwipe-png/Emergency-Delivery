fn main() {
    // FIRST: Parse .env and emit cargo directives BEFORE anything else
    if let Ok(content) = std::fs::read_to_string(".env") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let clean_value = value.trim().trim_matches('"').trim_matches('\'');
                println!("cargo:rustc-env={}={}", key.trim(), clean_value);
            }
        }
    }

    // Tell Cargo to rebuild if .env changes
    println!("cargo:rerun-if-changed=.env");

    // LAST: Call tauri_build AFTER env vars are injected
    tauri_build::build();
}