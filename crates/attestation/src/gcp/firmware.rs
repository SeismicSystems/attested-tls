//! On GCP check MRTD values map to Google endorsed firmware
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use attest_measure::dcap::DcapFirmware;
use thiserror::Error;

/// Maps MRTD values to GCP firmware to avoid re-fetching on subsequent
/// verification.
#[derive(Clone, Debug, Default)]
pub(crate) struct GcpFirmwareCache {
    cache: Arc<RwLock<HashMap<[u8; 48], DcapFirmware>>>,
}

impl GcpFirmwareCache {
    pub(crate) fn new() -> Self {
        Self { cache: Default::default() }
    }

    /// Retrieve firmware from cache or fetch it from Google if absent.
    pub(crate) fn get_or_fetch(
        &self,
        mrtd: [u8; 48],
    ) -> Result<DcapFirmware, GcpFirmwareCacheError> {
        if let Some(firmware) =
            self.cache.read().map_err(|_| GcpFirmwareCacheError::CacheLock)?.get(&mrtd).cloned()
        {
            return Ok(firmware);
        }

        let firmware = fetch_firmware(mrtd)?;
        self.cache
            .write()
            .map_err(|_| GcpFirmwareCacheError::CacheLock)?
            .insert(mrtd, firmware.clone());
        Ok(firmware)
    }
}

/// Fetch firmware from Google, offloading the blocking request when
/// possible.
pub(crate) fn fetch_firmware(mrtd: [u8; 48]) -> Result<DcapFirmware, GcpFirmwareCacheError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(handle.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) =>
        {
            tokio::task::block_in_place(|| {
                handle.block_on(async move {
                    tokio::task::spawn_blocking(move || DcapFirmware::from_google(mrtd))
                        .await
                        .map_err(|err| GcpFirmwareCacheError::Join(err.to_string()))?
                        .map_err(GcpFirmwareCacheError::from)
                })
            })
        }
        _ => DcapFirmware::from_google(mrtd).map_err(GcpFirmwareCacheError::from),
    }
}

#[derive(Debug, Error)]
pub(crate) enum GcpFirmwareCacheError {
    #[error("Cache lock poisoned")]
    CacheLock,
    #[error("Firmware fetch: {0}")]
    Firmware(#[from] attest_measure::dcap::GoogleError),
    #[error("Firmware fetch task join: {0}")]
    Join(String),
}
