use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Publish complete files without exposing a partially written database or report.
pub struct AtomicOutput {
    pub file: File,
    temporary: PathBuf,
    destination: PathBuf,
    force: bool,
}

impl AtomicOutput {
    pub fn new(destination: &Path, force: bool) -> Result<Self> {
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let name = destination
            .file_name()
            .context("output needs a filename")?
            .to_string_lossy();
        for _ in 0..32 {
            let temporary = parent.join(format!(
                ".{name}.{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&temporary) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        temporary,
                        destination: destination.to_owned(),
                        force,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("cannot allocate a temporary output file")
    }

    pub fn commit(self) -> Result<()> {
        self.file.sync_all()?;
        if self.force {
            fs::rename(&self.temporary, &self.destination)
                .with_context(|| format!("replace {}", self.destination.display()))?;
        } else {
            // Linking inside one directory provides atomic no-clobber publication.
            fs::hard_link(&self.temporary, &self.destination).with_context(|| {
                format!(
                    "create {}; use --force to replace an existing file",
                    self.destination.display()
                )
            })?;
            // Publication is complete. Drop cleans the temporary name; cleanup
            // failure must not turn a successful publication into a failed write.
        }
        Ok(())
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

pub fn write(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut output = AtomicOutput::new(path, force)?;
    output.file.write_all(bytes)?;
    output.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_outputs_survive_without_force_and_failed_writes_clean_up() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "weak-ca-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let path = dir.join("result");
        write(&path, b"original", false)?;
        assert!(write(&path, b"replacement", false).is_err());
        assert_eq!(fs::read(&path)?, b"original");
        write(&path, b"replacement", true)?;
        assert_eq!(fs::read(&path)?, b"replacement");
        assert_eq!(fs::read_dir(&dir)?.count(), 1);
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
