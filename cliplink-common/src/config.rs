use std::{fs::File, path::PathBuf};

pub struct Config;

impl Config {
    fn system_config_dir() -> PathBuf {
        use std::env;
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(env::var("PROGRAMDATA").unwrap_or(r"C:\ProgramData".to_string()))
        }

        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            PathBuf::from(env::var("XDG_CONFIG_DIRS").unwrap_or("/etc".to_string()))
        }

        #[cfg(target_os = "macos")]
        {
            PathBuf::from(env::var("XDG_CONFIG_DIRS").unwrap_or("/private/etc".to_string()))
        }

        #[cfg(not(any(unix, windows)))]
        compile_error!("Unsupported target OS for system_config_dir()");
    }

    pub fn dir_path() -> PathBuf {
        let mut config_path = Self::system_config_dir();
        config_path.push("/cliplink");

        if !config_path.exists() {
            std::fs::create_dir(&config_path).expect("failed to create config path");
        }

        config_path
    }

    pub fn file_path(file_name: &str) -> PathBuf {
        let mut config_path = Self::dir_path();
        config_path.push("/");
        config_path.push(file_name);

        if !config_path.exists() {
            File::create_new(&config_path).expect("failed to create config file");
        }

        config_path
    }
}
