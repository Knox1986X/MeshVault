use zeroize::{Zeroize, ZeroizeOnDrop};

/// Disables Linux core dumps (`PR_SET_DUMPABLE = 0`) so secret keys are never dumped to disk.
pub fn disable_core_dumps() -> bool {
    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: i32 = 4;
        // SAFETY: prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) is thread-safe and does not dereference pointers.
        let rc = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        rc == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Attempts to pin a secret byte slice in physical RAM (`mlock`) on Linux to avoid swap exposure.
pub fn lock_slice_in_ram(buf: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        if buf.is_empty() {
            return true;
        }
        // SAFETY: `buf.as_ptr()` is valid for `buf.len()` bytes.
        let rc = unsafe { mlock(buf.as_ptr().cast::<core::ffi::c_void>(), buf.len()) };
        rc == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = buf;
        false
    }
}

/// Unpins a previously locked byte slice from physical RAM (`munlock`) on Linux.
pub fn unlock_slice_in_ram(buf: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        if buf.is_empty() {
            return true;
        }
        // SAFETY: `buf.as_ptr()` is valid for `buf.len()` bytes.
        let rc = unsafe { munlock(buf.as_ptr().cast::<core::ffi::c_void>(), buf.len()) };
        rc == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = buf;
        false
    }
}

/// Fixed-size secret buffer that attempts `mlock` in RAM and guarantees `zeroize` + `munlock` on drop.
pub struct LockedSecretBox<const N: usize> {
    bytes: [u8; N],
    mlocked: bool,
}

impl<const N: usize> LockedSecretBox<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        let mut boxed = Self {
            bytes,
            mlocked: false,
        };
        boxed.mlocked = lock_slice_in_ram(&boxed.bytes);
        boxed
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }
}

impl<const N: usize> Zeroize for LockedSecretBox<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> Drop for LockedSecretBox<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.mlocked {
            let _ = unlock_slice_in_ram(&self.bytes);
            self.mlocked = false;
        }
    }
}

impl<const N: usize> ZeroizeOnDrop for LockedSecretBox<N> {}

#[cfg(target_os = "linux")]
extern "C" {
    fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
}
