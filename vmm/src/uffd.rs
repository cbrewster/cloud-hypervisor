// Copyright © 2025 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::mem::forget;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use log::info;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use vm_memory::GuestMemoryRegion;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::GuestRegionMmap;

/// Metadata about a guest memory region registered with userfaultfd.
///
/// This is sent to the external page fault handler so it knows how to
/// map page faults back to the snapshot memory file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestRegionUffdMapping {
    /// The base host virtual address of the memory region.
    pub base_host_virt_addr: u64,
    /// Size of the memory region in bytes.
    pub size: usize,
    /// Offset into the snapshot memory file where this region's data starts.
    pub offset: u64,
    /// Page size used for this region (4096 for regular pages, larger for huge pages).
    pub page_size: usize,
}

#[derive(Error, Debug)]
pub enum UffdError {
    /// Failed to create the userfaultfd.
    #[error("Failed to create userfaultfd")]
    Create(#[source] userfaultfd::Error),

    /// Failed to register a memory region with userfaultfd.
    #[error("Failed to register memory region with userfaultfd")]
    Register(#[source] userfaultfd::Error),

    /// Failed to connect to the userfaultfd handler socket.
    #[error("Failed to connect to userfaultfd handler socket")]
    Connect(#[source] std::io::Error),

    /// Failed to serialize the UFFD mappings.
    #[error("Failed to serialize UFFD mappings")]
    Serialize(#[source] serde_json::Error),

    /// Failed to send the UFFD file descriptor and mappings.
    #[error("Failed to send UFFD file descriptor and mappings: {0}")]
    SendHandshake(vmm_sys_util::errno::Error),
}

/// Create a userfaultfd, register all guest memory regions, and send the UFFD
/// file descriptor along with the region mappings to an external page fault
/// handler listening on a Unix domain socket.
///
/// This follows the same pattern as Firecracker's userfaultfd implementation:
/// 1. Create an anonymous UFFD with `EVENT_REMOVE` feature (for balloon support)
/// 2. Register each guest memory region with the UFFD
/// 3. Connect to the external handler's Unix socket
/// 4. Send the UFFD fd + JSON-serialized region mappings over the socket
///
/// The caller must ensure that guest memory regions are mapped as anonymous
/// (`MAP_PRIVATE | MAP_ANONYMOUS`) when using userfaultfd, since the external
/// handler will populate pages via `UFFDIO_COPY`.
///
/// Returns the `Uffd` object, which must be kept alive for the lifetime of the VM
/// to ensure page fault delivery continues working.
pub fn create_uffd_for_guest_memory(
    regions: &[std::sync::Arc<GuestRegionMmap>],
    uffd_socket_path: &Path,
) -> Result<Uffd, UffdError> {
    // Create the userfaultfd.
    //
    // We require EVENT_REMOVE to properly handle balloon device interactions
    // (madvise MADV_DONTNEED triggers UFFD_EVENT_REMOVE).
    let uffd = UffdBuilder::new()
        .require_features(FeatureFlags::EVENT_REMOVE)
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(false)
        .create()
        .map_err(UffdError::Create)?;

    // Build the region mappings and register each region with the UFFD.
    let mut backend_mappings = Vec::with_capacity(regions.len());
    let mut offset: u64 = 0;

    // SAFETY: FFI call. Trivially safe.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    for region in regions {
        let region_size = region.len() as usize;
        let region_ptr = region.as_ptr();

        // Register this memory region with the userfaultfd.
        // SAFETY: region_ptr is valid and region_size is the correct size of the mapping.
        uffd.register(region_ptr.cast(), region_size)
            .map_err(UffdError::Register)?;

        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: region_ptr as u64,
            size: region_size,
            offset,
            page_size,
        });

        offset += region_size as u64;

        info!(
            "Registered UFFD region: addr=0x{:x}, size=0x{:x}, offset=0x{:x}",
            region_ptr as u64, region_size, offset - region_size as u64
        );
    }

    // Send the UFFD fd and region mappings to the external handler.
    send_uffd_handshake(uffd_socket_path, &backend_mappings, &uffd)?;

    info!(
        "Userfaultfd handshake complete: {} regions registered, handler at {:?}",
        regions.len(),
        uffd_socket_path
    );

    Ok(uffd)
}

/// Send the userfaultfd file descriptor and region mapping metadata to an
/// external page fault handler over a Unix domain socket.
///
/// The handler receives:
/// - The UFFD file descriptor via SCM_RIGHTS
/// - A JSON-serialized `Vec<GuestRegionUffdMapping>` as the message payload
///
/// The socket is intentionally leaked (not closed) to avoid a race condition
/// between data delivery and connection close.
fn send_uffd_handshake(
    socket_path: &Path,
    mappings: &[GuestRegionUffdMapping],
    uffd: &Uffd,
) -> Result<(), UffdError> {
    let mappings_json = serde_json::to_string(mappings).map_err(UffdError::Serialize)?;

    let socket = UnixStream::connect(socket_path).map_err(UffdError::Connect)?;

    // Send the JSON payload with the UFFD file descriptor attached via SCM_RIGHTS.
    socket
        .send_with_fd(mappings_json.as_bytes(), uffd.as_raw_fd())
        .map_err(UffdError::SendHandshake)?;

    // Intentionally leak the socket to avoid a race between data delivery
    // and connection close, matching Firecracker's behavior.
    forget(socket);

    Ok(())
}
