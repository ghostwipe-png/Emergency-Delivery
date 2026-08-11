fn main() {
    tauri_build::build();

    // Automatically read your .env file and bake the variables into the binary at compile-time
    if let Ok(content) = std::fs::read_to_string(".env") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            
            if let Some((key, value)) = line.split_once('=') {
                // Remove surrounding quotes if they exist in the .env file
                let clean_value = value.trim().trim_matches('"').trim_matches('\'');
                
                // Tell Cargo to inject this as a compile-time environment variable
                println!("cargo:rustc-env={}={}", key.trim(), clean_value);
            }
        }
    }
}