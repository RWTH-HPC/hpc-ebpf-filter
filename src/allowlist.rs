use anyhow::{Context, Error, Result, anyhow};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use log::{error, info};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

const POLL_INTERVAL: Duration = Duration::from_secs(60);

pub fn load_allowlist(path: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open allowlist file {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(Error::from).with_context(|| {
            format!(
                "failed to read allowlist file {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("#") {
            continue;
        }
        if !trimmed.starts_with("/") {
            return Err(anyhow!(
                "invalid path in allowlist file {} at line {}: paths must be absolute",
                path.display(),
                line_number + 1
            ));
        }
        entries.push(PathBuf::from(trimmed));
    }

    Ok(entries)
}

pub struct AllowlistWatcher {
    stop_token: Arc<AtomicBool>,
    condvar: Arc<Condvar>,
    worker: Option<JoinHandle<()>>,
}

impl AllowlistWatcher {
    pub fn new(paths: Vec<PathBuf>, map: MapHandle) -> Self {
        if paths.is_empty() {
            info!("no allowlist provided, all user processes will be blocked");
        }

        let stop_token = Arc::new(AtomicBool::new(false));
        let condvar = Arc::new(Condvar::new());
        let stop_token_clone = stop_token.clone();
        let condvar_clone = condvar.clone();

        let worker = thread::spawn(move || {
            let mut map = map;
            let dummy_lock = Mutex::new(());
            loop {
                if stop_token_clone.load(Ordering::SeqCst) {
                    break;
                }

                if let Err(err) = refresh_all(&mut map, &paths) {
                    error!("failed to refresh allowlist: {err:#}");
                }

                let lock = dummy_lock.lock().unwrap();
                let _ = condvar_clone.wait_timeout(lock, POLL_INTERVAL);
            }
        });

        Self {
            stop_token,
            condvar,
            worker: Some(worker),
        }
    }
}

impl Drop for AllowlistWatcher {
    fn drop(&mut self) {
        self.stop_token.store(true, Ordering::SeqCst);
        self.condvar.notify_one();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn open_path(path: &Path) -> std::io::Result<Option<OwnedFd>> {
    let path_cstr = CString::new(path.as_os_str().as_bytes())?;

    let fd = unsafe { libc::open(path_cstr.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err);
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    Ok(Some(fd))
}

fn refresh_all(map: &mut MapHandle, paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        refresh_path(map, path)?;
    }
    Ok(())
}

fn refresh_path(map: &mut MapHandle, path: &Path) -> Result<()> {
    if let Some(fd) =
        open_path(path).with_context(|| format!("failed to open {}", path.display()))?
    {
        match add_file(map, fd.as_fd()) {
            Ok(true) => {
                info!("loaded new file into allowlist: {}", path.display());
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(err) => Err(anyhow::anyhow!(
                "failed to load file into allowlist: {} {err:#}",
                path.display()
            )),
        }
    } else {
        Ok(())
    }
}

fn add_file(map: &mut MapHandle, fd: BorrowedFd<'_>) -> Result<bool> {
    let key = fd.as_raw_fd() as u32;
    let value = [1u8];

    let res = map.update(
        &key.to_ne_bytes() as &[u8],
        &value as &[u8],
        MapFlags::NO_EXIST,
    );
    match res {
        Ok(_) => Ok(true),
        Err(err) => {
            if err.kind() == libbpf_rs::ErrorKind::AlreadyExists {
                Ok(false)
            } else {
                Err(anyhow::anyhow!("failed to update allowlist map: {err:#}"))
            }
        }
    }
}
