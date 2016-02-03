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

/// Maximum allowed length for a [message's `body`](struct.MpidMessage.html#method.new) (101,760
/// bytes).
pub const MAX_BODY_SIZE: usize = 102400 - 512 - super::MAX_HEADER_METADATA_SIZE;

use maidsafe_utilities::serialisation::serialise;
use sodiumoxide::crypto::sign::{self, PublicKey, SecretKey, Signature};
use super::{Error, MpidHeader};
use xor_name::XorName;

#[derive(PartialEq, Eq, Hash, Clone, Debug, RustcDecodable, RustcEncodable)]
struct Detail {
    recipient: XorName,
    body: Vec<u8>,
}

/// A full message including header and body which can be sent to or retrieved from the network.
#[derive(PartialEq, Eq, Hash, Clone, Debug, RustcDecodable, RustcEncodable)]
pub struct MpidMessage {
    header: MpidHeader,
    detail: Detail,
    signature: Signature,
}

impl MpidMessage {
    /// Constructor.
    ///
    /// `sender` and `metadata` are used to construct an `MpidHeader` member, accessed via the
    /// [`header()`](#method.header) getter.  For details on these arguments, see
    /// [MpidHeader::new()](struct.MpidHeader.html#method.new).
    ///
    /// `recipient` represents the name of the intended receiver of the message.
    ///
    /// `body` is arbitrary, user-supplied data representing the main portion of the message.  It
    /// must not exceed [`MAX_BODY_SIZE`](constant.MAX_BODY_SIZE.html).  It can be empty if desired.
    ///
    /// An error will be returned if `body` exceeds `MAX_BODY_SIZE`, if
    /// [MpidHeader::new()](struct.MpidHeader.html#method.new) fails or if
    /// serialisation during the signing process fails.
    pub fn new(sender: XorName,
               metadata: Vec<u8>,
               recipient: XorName,
               body: Vec<u8>,
               secret_key: &SecretKey)
               -> Result<MpidMessage, Error> {
        if body.len() > MAX_BODY_SIZE {
            return Err(Error::BodyTooLarge);
        }

        let header = try!(MpidHeader::new(sender, metadata, secret_key));

        let detail = Detail{
            recipient: recipient,
            body: body,
        };

        let recipient_and_body = try!(serialise(&detail));
        Ok(MpidMessage{
            header: header,
            detail: detail,
            signature: sign::sign_detached(&recipient_and_body, secret_key),
        })
    }

    /// Getter for `MpidHeader` member, created when calling `new()`.
    pub fn header(&self) -> &MpidHeader {
        &self.header
    }

    /// The name of the intended receiver of the message.
    pub fn recipient(&self) -> &XorName {
        &self.detail.recipient
    }

    /// Arbitrary, user-supplied data representing the main portion of the message.
    pub fn body(&self) -> &Vec<u8> {
        &self.detail.body
    }

    /// The name of the message, equivalent to the
    /// [`MpidHeader::name()`](../struct.MpidHeader.html#method.name).  As per that getter, this is
    /// relatively expensive, so its use should be minimised.
    pub fn name(&self) -> Result<XorName, Error> {
        self.header.name()
    }

    /// Validates the message and header signatures against the provided `PublicKey`.
    pub fn verify(&self, public_key: &PublicKey) -> bool {
        match serialise(&self.detail) {
            Ok(recipient_and_body) => {
                sign::verify_detached(&self.signature, &recipient_and_body, public_key) &&
                    self.header.verify(public_key)
            }
            Err(_) => false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use sodiumoxide::crypto::sign;
    use xor_name::XorName;

    #[test]
    fn mpid_message() {
        let (public_key, secret_key) = sign::gen_keypair();
        let sender: XorName = rand::random();
        let metadata = ::generate_random_bytes(128);
        let mpid_header = unwrap_result!(::MpidHeader::new(sender.clone(), metadata.clone(), &secret_key));
        let body = ::generate_random_bytes(1024);
        let receiver: XorName = rand::random();
        let mpid_message = unwrap_result!(MpidMessage::new(sender.clone(), metadata.clone(), receiver, body, &secret_key));
        assert!(mpid_message.verify(&public_key));
        assert_eq!(mpid_message.header().sender(), mpid_header.sender());
        assert_eq!(mpid_message.header().metadata(), mpid_header.metadata());
        assert!(mpid_message.header().guid() != mpid_header.guid());
    }
}
