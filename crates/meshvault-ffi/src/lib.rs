use serde::{Deserialize, Serialize};

/// States of the vault security lifecycle state machine.
/// Transitioning back to `Locked` immediately zeroizes MVK and decoded UI buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultSecurityState {
    Locked,
    UnlockingBiometric,
    UnlockingPassphrase,
    UnlockedFull,
    UnlockedSafePresentation,
    UnlockedDecoy,
    LockingZeroize,
}
