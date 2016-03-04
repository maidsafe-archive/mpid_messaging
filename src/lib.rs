// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! # MPID Messaging
//!
//! Types used by SAFE Vaults and SAFE Clients to send and receive messages.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/mpid_messaging/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

#[macro_use]
extern crate maidsafe_utilities;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate xor_name;

/// Length of the GUID (unique ID) of a message (16 bytes).
pub const GUID_SIZE: usize = 16;
/// Maximum allowed inbox size for an account (128 MiB).
pub const MAX_INBOX_SIZE: usize = 1 << 27;
/// Maximum allowed outbox size for an account (128 MiB).
pub const MAX_OUTBOX_SIZE: usize = 1 << 27;

mod error;
mod mpid_header;
mod mpid_message;
mod mpid_message_wrapper;

pub use error::Error;
pub use mpid_header::{MpidHeader, MAX_HEADER_METADATA_SIZE};
pub use mpid_message::{MpidMessage, MAX_BODY_SIZE};
pub use mpid_message_wrapper::MpidMessageWrapper;

use std::fmt::Write;

// Format a vector of bytes as a hexadecimal number, ellipsising all but the first and last three.
//
// For three bytes with values 1, 2, 3, the output will be "010203".  For more than six bytes, e.g.
// for fifteen bytes with values 1, 2, ..., 15, the output will be "010203..0d0e0f".
fn format_binary_array<V: AsRef<[u8]>>(input: V) -> String {
    let input_ref = input.as_ref();
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            unwrap_result!(write!(ret, "{:02x}", byte));
        }
        return ret;
    }
    format!("{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
            input_ref[0],
            input_ref[1],
            input_ref[2],
            input_ref[input_ref.len() - 3],
            input_ref[input_ref.len() - 2],
            input_ref[input_ref.len() - 1])
}

#[cfg(test)]
fn generate_random_bytes(size: usize) -> Vec<u8> {
    use rand::Rng;
    rand::thread_rng().gen_iter().take(size).collect()
}
