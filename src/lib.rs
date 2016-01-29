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
      private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
      unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
      unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;
extern crate xor_name;

use maidsafe_utilities::serialisation::serialise;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature};
use xor_name::XorName;

/// Maximum allowed size for `MessageHeader::metadata`
pub const MAX_HEADER_METADATA_SIZE: usize = 128;  // bytes
/// Maximum allowed size for `MpidMessage::msg_body`
pub const MAX_BODY_SIZE: usize = 102400 - 512 - MAX_HEADER_METADATA_SIZE;  // bytes
/// Length of the GUID (unique id of the header or full message)
pub const GUID_SIZE: usize = 16;
/// Maximum allowed inbox size for an account, currently set as 128 MiB
pub const MAX_INBOX_SIZE: usize = 1 << 27;  // bytes, i.e. 128 MiB
/// Maximum allowed oubox size for an account, currently set as 128 MiB
pub const MAX_OUTBOX_SIZE: usize = 1 << 27;  // bytes, i.e. 128 MiB

/// A simple struct holding the header's signable part
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
struct HeaderForSign {
    /// Sender's identification
    sender: XorName,
    /// unique identification
    guid: [u8; GUID_SIZE],
    /// Metadata field holding generic info of the message
    metadata: Vec<u8>,
}

/// To be used as a notification to the receiver
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct MpidHeader {
    /// Sender's identification
    sender_name: XorName,
    /// unique identification
    guid: [u8; GUID_SIZE],
    /// Metadata field holding generic info of the message
    metadata: Vec<u8>,
    /// Signature of the header
    signature: Signature,
}

impl MpidHeader {
    /// Construct for MpidHeader
    pub fn new(sender_name: XorName,
               metadata: Vec<u8>,
               secret_key: &SecretKey)
               -> Option<MpidHeader> {
        use rand::{self, Rng};
        if metadata.len() > MAX_HEADER_METADATA_SIZE {
            return None;
        }
        let mut guid = [0u8; GUID_SIZE];
        rand::thread_rng().fill_bytes(&mut guid);

        let encoded = Self::encode(&sender_name, &guid, &metadata);
        Some(MpidHeader{
            sender_name: sender_name,
            guid: guid,
            metadata: metadata,
            signature: sign::sign_detached(&encoded, secret_key),
        })
    }

    /// Getter for MpidHeader::sender_name
    pub fn sender_name(&self) -> &XorName {
        &self.sender_name
    }

    /// Getter for MpidHeader::guid
    pub fn guid(&self) -> &[u8; GUID_SIZE] {
        &self.guid
    }

    /// Getter for MpidHeader::metadata
    pub fn metadata(&self) -> &Vec<u8> {
        &self.metadata
    }

    /// Getter for MpidHeader::signature
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Help function to verify whether a MpidHeader is valid
    pub fn verify(&self, public_key: &PublicKey) -> bool {
        let encoded = Self::encode(&self.sender_name, &self.guid, &self.metadata);
        sign::verify_detached(&self.signature, &encoded, public_key)
    }

    fn encode(sender_name: &XorName, guid: &[u8; GUID_SIZE], metadata: &Vec<u8>) -> Vec<u8> {
        let header_for_sign = HeaderForSign {
            sender: sender_name.clone(),
            guid: guid.clone(),
            metadata: metadata.clone(),
        };
        match serialise(&header_for_sign) {
            Ok(encoded) => return encoded,
            Err(error) => {
                error!("Failed to encode MpidHeader: {:?}", error);
                return vec![];
            }
        }
    }
}

/// A simple struct holding the message's signable part
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
struct MessageForSign {
    /// Receiver's identification
    recipient: XorName,
    /// Content part of the message
    body: Vec<u8>,
}

/// Full message sending/fetching to/from the Network
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct MpidMessage {
    /// Header part of the message
    header: MpidHeader,
    /// Receiver's identification
    recipient: XorName,
    /// Content part of the message
    body: Vec<u8>,
    /// Signature of the message
    signature: Signature,
}

impl MpidMessage {
    /// Constructor for MpidMessage
    pub fn new(header: MpidHeader,
               recipient: XorName,
               body: Vec<u8>,
               secret_key: &SecretKey)
               -> Option<MpidMessage> {
        if body.len() > MAX_BODY_SIZE {
            return None;
        }

        let recipient_and_body = Self::encode(&recipient, &body);
        Some(MpidMessage {
            header: header,
            recipient: recipient,
            body: body,
            signature: sign::sign_detached(&recipient_and_body, secret_key),
        })
    }

    /// Getter for MpidMessage::header
    pub fn header(&self) -> &MpidHeader {
        &self.header
    }

    /// Getter for MpidMessage::recipient
    pub fn recipient(&self) -> &XorName {
        &self.recipient
    }

    /// Getter for MpidMessage::body
    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }

    /// Help function to verify whether a MpidMessage is valid
    pub fn verify(&self, public_key: &PublicKey) -> bool {
        let encoded = Self::encode(&self.recipient, &self.body);
        sign::verify_detached(&self.signature, &encoded, public_key) &&
            self.header.verify(public_key)
    }

    fn encode(recipient: &XorName, body: &Vec<u8>) -> Vec<u8> {
        let message_for_sign = MessageForSign {
            recipient: recipient.clone(),
            body: body.clone(),
        };
        match serialise(&message_for_sign) {
            Ok(encoded) => return encoded,
            Err(error) => {
                error!("Failed to encode MpidMessage: {:?}", error);
                return vec![];
            }
        }
    }
}

/// Help function to calculate the name of a MpidHeader
pub fn mpid_header_name(mpid_header: &MpidHeader) -> Option<XorName> {
    match serialise(&mpid_header) {
        Ok(encoded) => return Some(XorName(sha512::hash(&encoded[..]).0)),
        Err(error) => {
            error!("Failed to serialise Put request: {:?}", error);
        }
    }
    None
}

/// Help function to calculate the name of a MpidHeader
pub fn mpid_message_name(mpid_message: &MpidMessage) -> Option<XorName> {
    mpid_header_name(mpid_message.header())
}


/// Wrapper of mpid messaging operation
#[allow(variant_size_differences)]
#[derive(Clone, Debug, RustcDecodable, RustcEncodable)]
pub enum MpidMessageWrapper {
    /// Notification that the MPID Client has just connected to the network
    Online,
    /// Client send out an MpidMessage
    PutMessage(MpidMessage),
    /// Sender's MpidManager send out an MpidHeader to receiver's MpidManager 
    PutHeader(MpidHeader),
    /// Try to retrieve the message corresponding to the included header
    GetMessage(MpidHeader),
    /// List of headers to check for continued existence of corresponding messages in Sender's outbox
    OutboxHas(Vec<XorName>),
    /// Subset of list from Has request which still exist in Sender's outbox
    OutboxHasResponse(Vec<MpidHeader>),
    /// Retrieve the list of headers of all messages in Sender's outbox
    GetOutboxHeaders,
    /// The list of headers of all messages in Sender's outbox
    GetOutboxHeadersResponse(Vec<MpidHeader>),
}


#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use sodiumoxide::crypto::sign;
    use xor_name::XorName;

    fn generate_random_vec<T>(len: usize) -> Vec<T> where T: rand::Rand {
        let mut vec = Vec::<T>::with_capacity(len);
        for _ in 0..len {
            vec.push(rand::random::<T>());
        }
        vec
    }

    #[test]
    fn mpid_header() {
        let (public_key, secret_key) = sign::gen_keypair();
        let sender: XorName = rand::random();
        let long_metadata : Vec<u8> = generate_random_vec(129);
        match MpidHeader::new(sender, long_metadata, &secret_key) {
            Some(_) => panic!("failed in detecting a long metadata when compose a mpid_header"),
            None => {}
        }
        let metadata : Vec<u8> = generate_random_vec(128);
        match MpidHeader::new(sender, metadata, &secret_key) {
            Some(mpid_header) => assert!(mpid_header.verify(&public_key)),
            None => panic!("failed in compose a mpid_header"),
        }
    }

    #[test]
    fn mpid_message() {
        let (public_key, secret_key) = sign::gen_keypair();
        let sender: XorName = rand::random();
        let metadata : Vec<u8> = generate_random_vec(128);
        let mpid_header = match MpidHeader::new(sender, metadata, &secret_key) {
            Some(mpid_header) => mpid_header,
            None => panic!("failed in compose a mpid_header"),
        };
        let body : Vec<u8> = generate_random_vec(1024);
        let receiver: XorName = rand::random();
        match MpidMessage::new(mpid_header, receiver, body, &secret_key) {
            Some(mpid_message) => assert!(mpid_message.verify(&public_key)),
            None => panic!("failed in compose a mpid_message"),
        }
    }

}