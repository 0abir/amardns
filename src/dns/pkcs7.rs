use ring::digest::{SHA256, digest};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey};

/// Pinned ICANN Root CA v1 SubjectPublicKeyInfo (SPKI, RSA 2048-bit, valid until 2029)
pub const ICANN_ROOT_CA_V1_SPKI: &[u8] = &[
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xa0, 0xdb, 0x70, 0xb8, 0x4f, 0x34, 0xda, 0x9c, 0xd4, 0xd0, 0x7e, 0xbb, 0xea, 0x15, 0xbc,
    0xe9, 0xc9, 0x11, 0x2a, 0x1f, 0x61, 0x2f, 0x6a, 0xb9, 0xbd, 0x3f, 0x3d, 0x76, 0xa0, 0x9a, 0x0a,
    0xf7, 0xee, 0x93, 0x6e, 0x6e, 0x55, 0x53, 0x84, 0x8c, 0xf2, 0x2c, 0xf1, 0x82, 0x27, 0xc8, 0x0f,
    0x9a, 0xcf, 0x52, 0x1b, 0x54, 0xda, 0x28, 0xd2, 0x2c, 0x30, 0x8e, 0xdd, 0xfb, 0x92, 0x20, 0x33,
    0x2d, 0xd6, 0xc8, 0xf1, 0x0e, 0x10, 0x21, 0x88, 0x71, 0xfa, 0x84, 0x22, 0x4b, 0x5d, 0x47, 0x56,
    0x16, 0x7c, 0x9b, 0x9f, 0x5d, 0xc3, 0x11, 0x79, 0x9c, 0x14, 0xe2, 0xff, 0xc0, 0x74, 0xac, 0xdd,
    0x39, 0xd7, 0xe0, 0x38, 0xd8, 0xb0, 0x73, 0xaa, 0xfb, 0xd1, 0xdb, 0x84, 0xaf, 0x52, 0x22, 0xa8,
    0xf6, 0xd5, 0x9b, 0x94, 0xf4, 0xe6, 0x5d, 0x5e, 0xe8, 0x3f, 0x87, 0x90, 0x0b, 0xc7, 0x1a, 0x77,
    0xf5, 0x2e, 0xd3, 0x8f, 0x1a, 0xce, 0x02, 0x1d, 0x07, 0x69, 0x21, 0x47, 0x32, 0xda, 0x46, 0xae,
    0x00, 0x4c, 0xb6, 0xa5, 0xa2, 0x9c, 0x39, 0xc1, 0xc0, 0x4a, 0xf6, 0xd3, 0x1c, 0xae, 0xd3, 0x6d,
    0xbb, 0xc7, 0x18, 0xf0, 0x7e, 0xed, 0xf6, 0x80, 0xce, 0xd0, 0x01, 0x2e, 0x89, 0xde, 0x12, 0xba,
    0xee, 0x11, 0xcb, 0xa6, 0x7a, 0xd7, 0x0d, 0x7c, 0xf3, 0x08, 0x8d, 0x72, 0x9d, 0xbf, 0x55, 0x75,
    0x13, 0x70, 0xbb, 0x31, 0x22, 0x4a, 0xcb, 0xe8, 0xc0, 0xaa, 0xa4, 0x09, 0xaa, 0x36, 0x68, 0x40,
    0x60, 0x74, 0x9d, 0xe7, 0x19, 0x81, 0x43, 0x22, 0x52, 0xfe, 0xc9, 0x2b, 0x52, 0x0f, 0x41, 0x13,
    0x36, 0x09, 0x72, 0x65, 0x95, 0xcc, 0x89, 0xae, 0x6f, 0x56, 0x17, 0x16, 0x34, 0x73, 0x52, 0xa3,
    0x04, 0xed, 0xbd, 0x88, 0x82, 0x8a, 0xeb, 0xd7, 0xdc, 0x82, 0x52, 0x9c, 0x06, 0xe1, 0x52, 0x85,
    0x41, 0x02, 0x03, 0x01, 0x00, 0x01,
];

/// Pinned ICANN Root CA v2 SubjectPublicKeyInfo (SPKI, RSA 4096-bit, valid until 2045)
pub const ICANN_ROOT_CA_V2_SPKI: &[u8] = &[
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01,
    0x00, 0x9e, 0xa4, 0x38, 0xeb, 0xb9, 0xb8, 0xd1, 0xed, 0xe9, 0xff, 0xb9, 0x95, 0xa8, 0xec, 0xc0,
    0x27, 0xcc, 0x52, 0x08, 0xbd, 0x43, 0xd8, 0x11, 0xce, 0xdb, 0xf8, 0x09, 0x5e, 0x7d, 0xd9, 0x44,
    0x0d, 0x0d, 0x49, 0x12, 0x6a, 0x5f, 0xae, 0xfb, 0x7f, 0xe0, 0x25, 0xfd, 0x94, 0x9f, 0x52, 0x84,
    0x80, 0x51, 0xeb, 0x3c, 0x2b, 0x41, 0xe0, 0xef, 0xae, 0x3e, 0x57, 0x67, 0x69, 0x04, 0x8d, 0xb2,
    0x7c, 0x36, 0x77, 0x3a, 0xb0, 0xcf, 0xe8, 0x8d, 0xdc, 0xab, 0xe6, 0x34, 0x8b, 0xa9, 0xc0, 0xcf,
    0x1f, 0xd7, 0xc9, 0x83, 0xb8, 0xc2, 0x5b, 0x4d, 0x8a, 0x17, 0xc0, 0xad, 0xa9, 0x6b, 0x27, 0xa9,
    0xc5, 0xba, 0x8e, 0x34, 0xc8, 0x65, 0xc0, 0x96, 0x92, 0x0f, 0x65, 0x12, 0x2c, 0x5d, 0x17, 0xc4,
    0x00, 0x8c, 0x81, 0x20, 0x26, 0xd6, 0x6d, 0x7b, 0xe6, 0x21, 0x5d, 0xec, 0x8d, 0xd0, 0xa0, 0xf6,
    0x11, 0xa3, 0xbc, 0x53, 0x92, 0x1d, 0xd1, 0xb2, 0xef, 0x33, 0x2a, 0x61, 0xb8, 0xed, 0x4e, 0x08,
    0x62, 0xb3, 0x0e, 0xd7, 0xad, 0x71, 0x7f, 0x0a, 0xed, 0x2b, 0xe8, 0xb2, 0x17, 0x49, 0xc7, 0x79,
    0x4f, 0x22, 0x56, 0x33, 0xa9, 0x79, 0x74, 0x9d, 0x50, 0x18, 0x88, 0x27, 0x8d, 0x75, 0xe0, 0xf3,
    0x4c, 0xd8, 0xc4, 0x38, 0x76, 0x09, 0x38, 0xfe, 0x9d, 0x62, 0x86, 0x48, 0xf2, 0x72, 0x91, 0x26,
    0x5b, 0x4c, 0x91, 0x97, 0x02, 0x0a, 0x30, 0x44, 0xda, 0xf4, 0x2e, 0x48, 0xc6, 0x36, 0xc3, 0x8a,
    0x4e, 0x95, 0x69, 0x35, 0xb2, 0x41, 0xe3, 0x31, 0x65, 0xe3, 0x42, 0xc6, 0x73, 0x9e, 0x05, 0xee,
    0x34, 0x6e, 0x7a, 0xce, 0x26, 0xa5, 0x2f, 0x44, 0xcf, 0x10, 0x35, 0x56, 0x8d, 0x64, 0x63, 0xcc,
    0xe9, 0xeb, 0xb8, 0x75, 0x00, 0xb3, 0x82, 0x94, 0x63, 0xc6, 0x6c, 0xf8, 0xdb, 0x7c, 0x25, 0xd4,
    0xa5, 0x5c, 0xc8, 0xbc, 0xdb, 0x93, 0xca, 0xa0, 0xaa, 0x69, 0x11, 0x2b, 0x3b, 0xfd, 0x91, 0xb5,
    0x98, 0xf8, 0xd5, 0x39, 0x8a, 0x7b, 0x67, 0xb9, 0xed, 0xad, 0x18, 0xc9, 0x16, 0x09, 0xd4, 0x06,
    0x35, 0xb3, 0x54, 0xf3, 0xb1, 0xe3, 0x21, 0xe2, 0x26, 0x3d, 0x6e, 0xaf, 0xe3, 0xa9, 0xa8, 0xfd,
    0x7c, 0xa0, 0xfe, 0x58, 0x7e, 0xa6, 0x3e, 0xb4, 0xa9, 0xb3, 0xee, 0xf9, 0x5f, 0x44, 0x61, 0x8e,
    0x11, 0xdd, 0x3c, 0x6b, 0x45, 0xe0, 0x64, 0x84, 0x83, 0x34, 0xaa, 0x4c, 0x02, 0x8b, 0xe7, 0xe6,
    0x94, 0x54, 0x1d, 0x35, 0x8f, 0x08, 0x28, 0xdc, 0xdb, 0xcb, 0x67, 0xb3, 0xd3, 0x83, 0x3e, 0xfa,
    0xf5, 0x71, 0x08, 0xbe, 0x41, 0x2c, 0x13, 0xbf, 0xeb, 0xfc, 0xc2, 0x70, 0x39, 0x7a, 0xd1, 0xab,
    0xb1, 0xe6, 0x9d, 0xf3, 0xc4, 0x6f, 0xfe, 0x27, 0x9a, 0xab, 0x98, 0xa4, 0x30, 0x94, 0xd1, 0x0d,
    0xf5, 0xb8, 0x77, 0xd4, 0x98, 0xda, 0xe3, 0xdc, 0x30, 0x6b, 0xdf, 0x53, 0xa5, 0x5d, 0x40, 0xb4,
    0x61, 0x42, 0x4c, 0xc4, 0x55, 0x34, 0x0d, 0x00, 0x9d, 0x51, 0x8b, 0x69, 0x4e, 0xa0, 0x96, 0xdb,
    0x8f, 0x09, 0xca, 0xf8, 0xe5, 0x3d, 0x3a, 0x14, 0x93, 0xfc, 0xea, 0x9d, 0x8c, 0x90, 0xc9, 0x02,
    0x14, 0xc0, 0xb2, 0xd7, 0x54, 0x9e, 0xba, 0xfc, 0x58, 0x15, 0x3c, 0xd3, 0x13, 0x3b, 0xe4, 0xc2,
    0x1a, 0x69, 0x38, 0xd2, 0x04, 0x2b, 0xd9, 0xd7, 0x0a, 0xe8, 0xa4, 0x08, 0xb6, 0x85, 0x86, 0xf4,
    0xb5, 0xe7, 0x53, 0x1f, 0xa5, 0x9a, 0xad, 0x25, 0xb7, 0x30, 0x7f, 0x47, 0x70, 0x4a, 0x06, 0x1b,
    0x3b, 0x36, 0x18, 0x3d, 0xe1, 0x0c, 0x1d, 0x1a, 0xd9, 0xe0, 0xa9, 0xf9, 0x37, 0x40, 0xb3, 0xc5,
    0x29, 0xf7, 0x8e, 0x12, 0x8d, 0x8e, 0xd4, 0x57, 0x82, 0x71, 0xb0, 0xe0, 0xbb, 0x4f, 0x16, 0xe6,
    0x91, 0x02, 0x03, 0x01, 0x00, 0x01,
];

/// Lightweight, zero-allocation ASN.1 DER element view
#[derive(Debug, Clone, Copy)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub _header_len: usize,
    pub content: &'a [u8],
    pub full_bytes: &'a [u8],
}

impl<'a> DerElement<'a> {
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), String> {
        if input.is_empty() {
            return Err("Unexpected EOF in DER stream".to_string());
        }
        let tag = input[0];
        if input.len() < 2 {
            return Err("Truncated DER element header".to_string());
        }
        let (len, header_len) = if input[1] & 0x80 == 0 {
            (input[1] as usize, 2)
        } else {
            let num_octets = (input[1] & 0x7f) as usize;
            if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
                return Err("Invalid DER length octets".to_string());
            }
            let mut l: usize = 0;
            for i in 0..num_octets {
                l = (l << 8) | (input[2 + i] as usize);
            }
            (l, 2 + num_octets)
        };

        if input.len() < header_len + len {
            return Err(format!(
                "DER element length ({}) exceeds remaining buffer ({})",
                header_len + len,
                input.len()
            ));
        }

        let full_bytes = &input[..header_len + len];
        let content = &input[header_len..header_len + len];
        let remainder = &input[header_len + len..];

        Ok((
            DerElement {
                tag,
                _header_len: header_len,
                content,
                full_bytes,
            },
            remainder,
        ))
    }

    pub fn children(&self) -> Result<Vec<DerElement<'a>>, String> {
        let mut res = Vec::new();
        let mut rem = self.content;
        while !rem.is_empty() {
            let (elem, next_rem) = DerElement::parse(rem)?;
            res.push(elem);
            rem = next_rem;
        }
        Ok(res)
    }
}

/// Cryptographically validates the IANA Root Trust Anchor XML against its detached PKCS#7 / S/MIME signature (.p7s)
/// using pinned ICANN Root CA keys (RFC 7958 Section 3, RFC 5652).
pub fn verify_iana_root_anchors_smime(xml_bytes: &[u8], p7s_bytes: &[u8]) -> Result<(), String> {
    // 1. Parse top-level ContentInfo SEQUENCE
    let (content_info, _) = DerElement::parse(p7s_bytes)?;
    if content_info.tag != 0x30 {
        return Err("PKCS7 signature is not a valid DER SEQUENCE".to_string());
    }
    let ci_children = content_info.children()?;
    if ci_children.len() < 2 {
        return Err("PKCS7 ContentInfo missing signed-data content".to_string());
    }

    // Check contentType is 1.2.840.113549.1.7.2 (id-signedData)
    let signed_data_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    if ci_children[0].tag != 0x06 || ci_children[0].content != signed_data_oid {
        return Err("PKCS7 ContentInfo contentType is not id-signedData".to_string());
    }

    // 2. Parse SignedData [0] EXPLICIT
    let signed_data_container = ci_children[1];
    if signed_data_container.tag != 0xA0 {
        return Err("PKCS7 SignedData container tag mismatch".to_string());
    }
    let (signed_data, _) = DerElement::parse(signed_data_container.content)?;
    if signed_data.tag != 0x30 {
        return Err("PKCS7 SignedData payload is not a valid SEQUENCE".to_string());
    }

    let sd_children = signed_data.children()?;
    let certs_elem = sd_children
        .iter()
        .find(|c| c.tag == 0xA0)
        .ok_or_else(|| "No certificates found in PKCS7 SignedData".to_string())?;

    let signer_infos_elem = sd_children
        .iter()
        .rfind(|c| c.tag == 0x31)
        .ok_or_else(|| "No signerInfos found in PKCS7 SignedData".to_string())?;

    // 3. Parse certificates in container
    let certs = certs_elem.children()?;
    if certs.is_empty() {
        return Err("PKCS7 certificate set is empty".to_string());
    }

    // 4. Parse SignerInfo
    let signer_infos = signer_infos_elem.children()?;
    if signer_infos.is_empty() {
        return Err("PKCS7 signerInfos set is empty".to_string());
    }
    let signer_info = signer_infos[0];
    let si_children = signer_info.children()?;

    let signed_attrs = si_children
        .iter()
        .find(|c| c.tag == 0xA0)
        .ok_or_else(|| "SignedAttributes missing in PKCS7 SignerInfo".to_string())?;

    let signature_elem = si_children
        .iter()
        .find(|c| c.tag == 0x04)
        .ok_or_else(|| "Signature OCTET STRING missing in PKCS7 SignerInfo".to_string())?;

    // 5. Verify messageDigest attribute in signedAttrs matches SHA-256(xml_bytes)
    let xml_hash = digest(&SHA256, xml_bytes);
    let mut found_digest = false;
    let message_digest_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

    for attr in signed_attrs.children()? {
        let attr_parts = attr.children()?;
        if attr_parts.len() >= 2
            && attr_parts[0].tag == 0x06
            && attr_parts[0].content == message_digest_oid
        {
            let set_children = attr_parts[1].children()?;
            if !set_children.is_empty() && set_children[0].tag == 0x04 {
                if set_children[0].content != xml_hash.as_ref() {
                    return Err(
                        "XML SHA-256 digest does not match S/MIME messageDigest".to_string()
                    );
                }
                found_digest = true;
                break;
            }
        }
    }

    if !found_digest {
        return Err("messageDigest attribute not found in SignedAttributes".to_string());
    }

    // 6. Construct DER for SignedAttributes signature verification (replace tag 0xA0 with 0x31 SET OF per RFC 2315 / 5652)
    let mut signed_attrs_der = signed_attrs.full_bytes.to_vec();
    signed_attrs_der[0] = 0x31;

    // 7. Find leaf certificate by matching SID (IssuerAndSerialNumber) from SignerInfo
    let sid = si_children
        .get(1)
        .ok_or_else(|| "SignerInfo missing SID".to_string())?;
    let sid_parts = sid.children().unwrap_or_default();
    let sid_serial = sid_parts.iter().find(|p| p.tag == 0x02);

    let mut signer_cert: Option<DerElement> = None;
    for cert in &certs {
        let x509_children = cert.children()?;
        if x509_children.len() >= 3 {
            let tbs = x509_children[0];
            let tbs_children = tbs.children()?;
            if let Some(cert_serial) = tbs_children.iter().find(|c| c.tag == 0x02) {
                if let Some(target_serial) = sid_serial {
                    if cert_serial.content == target_serial.content {
                        signer_cert = Some(*cert);
                        break;
                    }
                }
            }
        }
    }

    let leaf = signer_cert
        .or_else(|| certs.iter().cloned().next_back())
        .ok_or_else(|| "No signer certificate found".to_string())?;

    let leaf_children = leaf.children()?;
    if leaf_children.len() < 3 {
        return Err("Invalid X.509 leaf certificate structure in PKCS7 container".to_string());
    }

    let leaf_tbs = leaf_children[0];
    let leaf_sig_val = leaf_children[2];
    let leaf_tbs_children = leaf_tbs.children()?;

    // Extract leaf RSAPublicKey (PKCS#1 DER) from leaf SPKI
    let leaf_spki = leaf_tbs_children
        .iter()
        .find(|c| {
            if c.tag == 0x30 {
                if let Ok(parts) = c.children() {
                    if parts.len() == 2 && parts[0].tag == 0x30 && parts[1].tag == 0x03 {
                        return true;
                    }
                }
            }
            false
        })
        .ok_or_else(|| "Leaf certificate SubjectPublicKeyInfo not found".to_string())?;

    let leaf_spki_parts = leaf_spki.children()?;
    if leaf_spki_parts.len() < 2 || leaf_spki_parts[1].tag != 0x03 {
        return Err("Invalid leaf SPKI structure".to_string());
    }
    let leaf_bit_string = leaf_spki_parts[1].content;
    let leaf_rsa_pkcs1 = if !leaf_bit_string.is_empty() && leaf_bit_string[0] == 0x00 {
        &leaf_bit_string[1..]
    } else {
        leaf_bit_string
    };

    // 8. Cryptographically verify SignedAttributes signature with Leaf RSAPublicKey
    let leaf_pubkey = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, leaf_rsa_pkcs1);
    leaf_pubkey
        .verify(&signed_attrs_der, signature_elem.content)
        .map_err(|e| {
            format!(
                "Leaf signature verification of signed attributes failed: {:?}",
                e
            )
        })?;

    // 9. Cryptographically verify Leaf certificate signature with Pinned ICANN Root CA (v1 or v2)
    let leaf_sig_bytes = if !leaf_sig_val.content.is_empty() && leaf_sig_val.content[0] == 0x00 {
        &leaf_sig_val.content[1..] // strip leading unused bits in BIT STRING
    } else {
        leaf_sig_val.content
    };

    // Extract PKCS#1 RSAPublicKey from Root CA SPKIs
    fn extract_pkcs1_from_spki(spki_der: &[u8]) -> Result<&[u8], String> {
        let (spki_elem, _) = DerElement::parse(spki_der)?;
        let parts = spki_elem.children()?;
        if parts.len() < 2 || parts[1].tag != 0x03 {
            return Err("Invalid SPKI DER".to_string());
        }
        let bit_string = parts[1].content;
        if !bit_string.is_empty() && bit_string[0] == 0x00 {
            Ok(&bit_string[1..])
        } else {
            Ok(bit_string)
        }
    }

    let root_v1_pkcs1 = extract_pkcs1_from_spki(ICANN_ROOT_CA_V1_SPKI)?;
    let root_v2_pkcs1 = extract_pkcs1_from_spki(ICANN_ROOT_CA_V2_SPKI)?;

    let mut ca_verified = false;
    for (ca_name, pkcs1_key, alg) in [
        (
            "ICANN Root CA v1",
            root_v1_pkcs1,
            &RSA_PKCS1_2048_8192_SHA256,
        ),
        (
            "ICANN Root CA v2 (SHA-256)",
            root_v2_pkcs1,
            &RSA_PKCS1_2048_8192_SHA256,
        ),
        (
            "ICANN Root CA v2 (SHA-512)",
            root_v2_pkcs1,
            &RSA_PKCS1_2048_8192_SHA512,
        ),
    ] {
        let root_pubkey = UnparsedPublicKey::new(alg, pkcs1_key);
        if root_pubkey
            .verify(leaf_tbs.full_bytes, leaf_sig_bytes)
            .is_ok()
        {
            ca_verified = true;
            tracing::debug!("[dnssec] S/MIME signer verified against pinned {}", ca_name);
            break;
        }
    }

    if !ca_verified {
        return Err(
            "Leaf certificate signature could not be verified by pinned ICANN Root CA keys"
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_element_parse_primitives() {
        // Tag 0x04 (OCTET STRING), length 4, bytes: 01 02 03 04
        let input = [0x04, 0x04, 0x01, 0x02, 0x03, 0x04];
        let (elem, rem) = DerElement::parse(&input).expect("parse DER");
        assert_eq!(elem.tag, 0x04);
        assert_eq!(elem.content, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(elem.full_bytes, &input[..]);
        assert!(rem.is_empty());
    }

    #[test]
    fn test_der_element_long_length() {
        let mut buf = vec![0x30, 0x82, 0x01, 0x00];
        buf.resize(4 + 256, 0xAA);
        let (elem, rem) = DerElement::parse(&buf).expect("parse long DER");
        assert_eq!(elem.tag, 0x30);
        assert_eq!(elem.content.len(), 256);
        assert!(rem.is_empty());
    }

    #[test]
    fn test_verify_iana_root_anchors_smime_tampered_xml() {
        let sample_xml = b"<TrustAnchor id=\"sample\"><Zone>.</Zone></TrustAnchor>";
        let sample_p7s = [0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04]; // invalid / bogus p7s
        let result = verify_iana_root_anchors_smime(sample_xml, &sample_p7s);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_real_iana_root_anchors_smime_roundtrip() {
        let xml = include_bytes!("../../tests/fixtures/root-anchors.xml");
        let p7s = include_bytes!("../../tests/fixtures/root-anchors.p7s");

        let result = verify_iana_root_anchors_smime(xml, p7s);
        assert!(
            result.is_ok(),
            "Real IANA root-anchors S/MIME verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_real_iana_root_anchors_smime_detects_tampering() {
        let mut xml = include_bytes!("../../tests/fixtures/root-anchors.xml").to_vec();
        let p7s = include_bytes!("../../tests/fixtures/root-anchors.p7s");

        // Tamper with 1 byte in the XML
        if let Some(pos) = xml.iter().position(|&b| b == b'8') {
            xml[pos] = b'9';
        }

        let result = verify_iana_root_anchors_smime(&xml, p7s);
        assert!(
            result.is_err(),
            "Verification should have failed on tampered XML"
        );
        assert!(
            result
                .unwrap_err()
                .contains("XML SHA-256 digest does not match S/MIME messageDigest")
        );
    }

    #[test]
    fn test_verify_real_iana_root_anchors_smime_detects_signature_corruption() {
        let xml = include_bytes!("../../tests/fixtures/root-anchors.xml");
        let mut p7s = include_bytes!("../../tests/fixtures/root-anchors.p7s").to_vec();

        // Tamper with the signature bytes at the end
        let len = p7s.len();
        p7s[len - 5] ^= 0xFF;

        let result = verify_iana_root_anchors_smime(xml, &p7s);
        assert!(
            result.is_err(),
            "Verification should have failed on corrupted signature"
        );
    }
}
