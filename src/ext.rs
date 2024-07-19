use crate::def::{SignatureScheme, SupportedGroup, to_u16, u16_to_u8_pair};
use crate::err::Mutter;

#[derive(Clone, Debug)]
pub struct ClientExtensions(
    ServerNameExt,
    SupportedVersionExt,
    SignatureSchemeExtensions,
    SupportedGroupExtensions,
    KeyShareExtensions,
);

impl TryFrom<(&str, &[SignatureScheme], &[SupportedGroup], &[KeyShare])> for ClientExtensions {
    type Error = Mutter;

    fn try_from((server_name, schemes, groups, key_shares): (&str, &[SignatureScheme], &[SupportedGroup], &[KeyShare])) -> Result<Self, Mutter> {
        if server_name.is_empty() ||
            schemes.is_empty() ||
            groups.is_empty() ||
            key_shares.is_empty() {
            return Err(Mutter::BadInput)
        }
        Ok(Self(ServerNameExt::try_from(server_name)?,
                SupportedVersionExt::new(PeerType::Client),
                SignatureSchemeExtensions::try_from(schemes)?,
                SupportedGroupExtensions::try_from(groups)?,
                KeyShareExtensions::try_from((PeerType::Client, key_shares))?))
    }
}

#[allow(dead_code)]
impl ClientExtensions {
    pub fn server_name_extension(&self) -> &ServerNameExt {
        &self.0
    }

    pub fn supported_ver_extension(&self) -> &SupportedVersionExt {
        &self.1
    }

    pub fn signature_scheme_extensions(&self) -> &SignatureSchemeExtensions {
        &self.2
    }

    pub fn supported_group_extensions(&self) -> &SupportedGroupExtensions {
        &self.3
    }

    pub fn key_share_extensions(&self) -> &KeyShareExtensions {
        &self.4
    }

    pub fn size(&self) -> usize {
        self.server_name_extension().size() +
            self.supported_ver_extension().size() +
            self.signature_scheme_extensions().size() +
            self.supported_group_extensions().size() +
            self.key_share_extensions().size()
    }

    pub fn serialize(&self, bytes: &mut [u8], pos: usize) -> usize {
        if pos + self.size() > bytes.len() {
            0
        } else {
            let mut i = pos;
            i += self.server_name_extension().serialize(bytes, i);
            i += self.supported_ver_extension().serialize(bytes, i);
            i += self.signature_scheme_extensions().serialize(bytes, i);
            i += self.supported_group_extensions().serialize(bytes, i);
            i += self.key_share_extensions().serialize(bytes, i);
            i - pos
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerNameExt {
    name: String,
}

#[allow(dead_code)]
impl TryFrom<&str> for ServerNameExt {
    type Error = Mutter;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        if name.len() > 0 && name.len() < 64 {
            Ok(ServerNameExt::new(name))
        } else {
            Err(Mutter::ExtensionData)
        }
    }
}

#[allow(dead_code)]
impl ServerNameExt {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned()
        }
    }

    pub fn size(&self) -> usize {
        9 + self.name.len()
    }

    pub fn serialize(&self, bytes: &mut [u8], i: usize) -> usize {
        let len = self.size();
        if i + len > bytes.len() {
            0
        } else {
            let n = len as u8;
            bytes[i..i + len].copy_from_slice(
                &[[0, 0, 0, n - 4, 0, n - 6, 0, 0, n - 9].as_slice(), self.name.as_bytes()].concat());
            len
        }
    }

    pub fn deserialize(ctx: PeerType, bytes: &[u8], i: usize) -> Result<(Self, usize), Mutter> {
        let inp_size = bytes.len();
        if ctx != PeerType::Client || inp_size < 9 {
            Err(Mutter::BadInput)
        } else {
            if (bytes[i], bytes[i + 1]) != (0, 0) {
                return Err(Mutter::ExtensionType)
            }
            let ext_data_len = to_u16(bytes[i + 2], bytes[i + 3]);
            let list_len = to_u16(bytes[i + 4], bytes[i + 5]); // list of len = 1
            if ext_data_len != list_len + 2 {
                return Err(Mutter::ExtensionLen)
            }
            if bytes[i + 6] != 0 { // indicates DNS hostname
                return Err(Mutter::ExtensionData)
            }
            let name_len = to_u16(bytes[i + 7], bytes[i + 8]) as usize;
            if (9 + name_len) > inp_size {
                return Err(Mutter::BadInput)
            }
            let s: &str = core::str::from_utf8(&bytes[9..9 + name_len])
                .map_err(|_| Mutter::ExtensionData)?;
            Ok((Self::new(s), 9 + name_len))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PeerType {
    Client,
    Server
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SupportedVersionExt {
    ctx: PeerType,
}

#[allow(dead_code)]
// support only version 1.3 = (0x03, 0x04)
impl SupportedVersionExt {
    const CLIENT_EXT_SIZE: usize = 7;
    const SERVER_EXT_SIZE: usize = 6;

    pub fn new(ctx: PeerType) -> Self {
        Self {
            ctx
        }
    }

    pub fn size(&self) -> usize {
        if self.ctx == PeerType::Client {
            7
        } else {
            6
        }
    }

    pub fn deserialize(ctx: PeerType, bytes: &[u8], i: usize) -> Result<(Self, usize), Mutter> {
        let req_size = if ctx == PeerType::Client {
            SupportedVersionExt::CLIENT_EXT_SIZE
        } else {
            SupportedVersionExt::SERVER_EXT_SIZE
        };
        if bytes.len() < req_size {
            Err(Mutter::BadInput)
        } else {
            if (ctx == PeerType::Client &&
                bytes[i..i + req_size] == [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]) ||
                (bytes[i..i + req_size] == [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]) {
                Ok((Self::new(ctx), req_size))
            } else {
                Err(Mutter::ExtensionData)
            }
        }
    }

    pub fn serialize(&self, bytes: &mut [u8], i: usize) -> usize {
        if bytes.len() < i + self.size() {
            0
        } else {
            if self.ctx == PeerType::Client {
                bytes[i..i + self.size()].copy_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
            } else {
                bytes[i..i + self.size()].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
            }
            self.size()
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyShare {
    group: SupportedGroup,
    public_key: Vec<u8>
}

#[allow(dead_code)]
impl TryFrom<(u16, &[u8])> for KeyShare {
    type Error = Mutter;

    fn try_from((group_code, key): (u16, &[u8])) -> Result<Self, Mutter> {
        let group: SupportedGroup = group_code.try_into()?;
        if group.key_size() == key.len() {
            Ok(Self::new(group, key.into()))
        } else {
            Err(Mutter::BadInput)
        }
    }
}

#[allow(dead_code)]
impl KeyShare {
    fn new(group: SupportedGroup, public_key: Vec<u8>) -> Self {
        Self {
            group,
            public_key
        }
    }

    pub fn x25519(pub_key: &[u8; 32]) -> Self {
        Self::new(SupportedGroup::X25519, pub_key.to_vec())
    }

    pub fn secp256r1(pub_key: &[u8; 32]) -> Self {
        Self::new(SupportedGroup::Secp256r1, pub_key.to_vec())
    }

    // 2 bytes for the SupportedGroup id.
    // 2 bytes to indicate the size of the public key.
    // N bytes of the public key.
    pub fn size(&self) -> usize {
        match self.group {
            SupportedGroup::Secp256r1 | SupportedGroup::X25519 => 2 + 2 + self.public_key.len(),
            _ => 0
        }
    }

    pub fn serialize(&self, bytes: &mut [u8], i: usize) -> usize {
        if i + self.size() + 2 > bytes.len() {
            0
        } else {
            match self.group {
                SupportedGroup::Secp256r1 | SupportedGroup::X25519 => {
                    // 1. 2 bytes for storing the size of data following this field
                    (bytes[i], bytes[i + 1]) = u16_to_u8_pair(self.size() as u16);
                    // 2. 2 bytes for curve/group id.
                    (bytes[i + 2], bytes[i + 3]) = u16_to_u8_pair(self.group as u16); // group id
                    // 3. 2 bytes for the length of the key that follows
                    (bytes[i + 4], bytes[i + 5]) = u16_to_u8_pair(self.public_key.len() as u16);
                    // 4. bytes representing the key
                    bytes[i + 6..i + 6 + self.public_key.len()].copy_from_slice(&self.public_key); // the key bytes
                    2 + self.size() // 2 bytes for the initial header as shown in 1, above.
                }
                _ => return 0
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyShareExtensions(PeerType, Vec<KeyShare>);

impl TryFrom<(PeerType, &[KeyShare])> for KeyShareExtensions {
    type Error = Mutter;

    fn try_from((ctx, key_shares): (PeerType, &[KeyShare])) -> Result<Self, Mutter> {
        if ctx == PeerType::Server && key_shares.len() != 1 {
            Err(Mutter::BadInput)
        } else if ctx == PeerType::Client && key_shares.len() == 0 {
            Err(Mutter::BadInput)
        } else {
            let mut dup = [true, false, false];
            for ksx in key_shares {
                let sln = SupportedGroup::try_from(ksx.group as u16)?.sln();
                if dup[sln] {
                    Err(Mutter::DuplicateSupportedGroup)?
                } else {
                    dup[sln] = true;
                }
            }
            Ok(Self::new(ctx, key_shares.into()))
        }
    }
}

#[allow(dead_code)]
impl KeyShareExtensions {
    fn new(ctx: PeerType, ext: Vec<KeyShare>) -> Self {
        Self(ctx, ext)
    }

    pub fn client(&self) -> bool {
        self.0 == PeerType::Client
    }

    pub fn server(&self) -> bool {
        self.0 == PeerType::Server
    }

    pub fn extensions(&self) -> &[KeyShare] {
        &self.1
    }

    pub fn size(&self) -> usize {
        // 2 bytes for indicating key share extension + 2 bytes for the total size of the extension data
        let mut size = 4;
        for key_share_ext in self.extensions() {
            // ext.size() is the number of bytes required to represent the extension data sans its length.
            // each extension needs two additional bytes to store its size/len.
            size += key_share_ext.size() + 2;
        }
        size
    }

    pub fn serialize(&self, bytes: &mut [u8], pos: usize) -> usize {
        let size = self.size();
        if size >= (1 << 16) - 1 || (pos + size) > bytes.len() {
            0
        } else {
            let mut i = pos;
            (bytes[i], bytes[i + 1]) = (0, 0x33);
            i += 2;
            // server shares only one key; client may share one or more keys.
            // client stores the size of the list of key shares that follows.
            if self.client() {
                (bytes[i], bytes[i + 1]) = u16_to_u8_pair((size - 4) as u16);
                i += 2;
            }
            for ext in self.extensions() {
                i += ext.serialize(bytes, i);
            }
            assert_eq!(i - pos, size);
            size
        }
    }
}

#[derive(Clone, Debug)]
pub struct SupportedGroupExt(SupportedGroup);

impl TryFrom<u16> for SupportedGroupExt {
    type Error = Mutter;

    fn try_from(val: u16) -> Result<Self, Mutter> {
        Ok(Self(SupportedGroup::try_from(val)?))
    }
}

#[allow(dead_code)]
impl SupportedGroupExt {
    fn new(g: SupportedGroup) -> Self {
        Self(g)
    }

    pub fn size(&self) -> usize {
        2
    }

    pub fn serialize(&self, bytes: &mut [u8], pos: usize) -> usize {
        if pos + self.size() > bytes.len() {
            0
        } else {
            (bytes[pos], bytes[pos + 1]) = u16_to_u8_pair(self.0 as u16);
            2
        }
    }
}

#[derive(Clone, Debug)]
pub struct SupportedGroupExtensions(Vec<SupportedGroupExt>);

impl TryFrom<&[SupportedGroup]> for SupportedGroupExtensions {
    type Error = Mutter;

    fn try_from(groups: &[SupportedGroup]) -> Result<SupportedGroupExtensions, Mutter> {
        if !groups.is_empty() {
            let mut list_grp_ext = Vec::new();
            let mut groups_dup: Vec<bool> = vec![true, false, false];
            for g in groups.iter() {
                let i = g.sln();
                if groups_dup[i] { // this is a duplicate entry
                    return Err(Mutter::DuplicateSupportedGroup)
                } else {
                    groups_dup[i] = true;
                    list_grp_ext.push(SupportedGroupExt::new(*g));
                }
            }
            Ok(SupportedGroupExtensions(list_grp_ext))
        } else {
            Err(Mutter::SupportedGroupLen)
        }
    }
}

#[allow(dead_code)]
impl SupportedGroupExtensions {
    pub fn supported_groups(&self) -> &[SupportedGroupExt] {
        &self.0
    }

    pub fn size(&self) -> usize {
        // the header needs 6 bytes: 2 for extension type + 2 for list size + 2 for data size.
        6 + self.supported_groups().len() * 2
    }

    pub fn serialize(&self, bytes: &mut [u8], pos: usize) -> usize {
        let len = self.supported_groups().len() * 2; // each signature scheme takes two bytes.
        // the header needs 6 bytes: 2 for extension type + 2 for list size + 2 for data size.
        if (pos + 6 + len) > bytes.len() {
            0
        } else {
            let mut i = pos;
            (bytes[i], bytes[i + 1]) = (0, 0x0a);
            (bytes[i + 2], bytes[i + 3]) = u16_to_u8_pair((len + 2) as u16);
            (bytes[i + 4], bytes[i + 5]) = u16_to_u8_pair(len as u16);
            i += 6;
            for ext in self.supported_groups() {
                i += ext.serialize(bytes, i);
            }
            assert_eq!(i - pos, 6 + len);
            6 + len
        }
    }
}

#[derive(Clone, Debug)]
pub struct SigAlgExt {
    scheme: SignatureScheme,
}

#[allow(dead_code)]
impl SigAlgExt {
    pub const EXT_SIZE: usize = 2;

    fn new(scheme: SignatureScheme) -> Self {
        Self {
            scheme
        }
    }

    pub fn size(&self) -> usize {
        2
    }

    pub fn deserialize(ctx: PeerType, bytes: &[u8], i: usize) -> Result<(Self, usize), Mutter> {
        if ctx != PeerType::Client || i + Self::EXT_SIZE > bytes.len() {
            Err(Mutter::BadInput)
        } else {
            let scheme = SignatureScheme::try_from(to_u16(bytes[i], bytes[i + 1]))?;
            Ok((Self::new(scheme), 2))
        }
    }

    pub fn serialize(&self, bytes: &mut [u8], i: usize) -> usize {
        if i + self.size() > bytes.len() {
            0
        } else {
            (bytes[i], bytes[i + 1]) = u16_to_u8_pair(self.scheme as u16);
            self.size()
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSchemeExtensions(Vec<SigAlgExt>);

impl TryFrom<&[SignatureScheme]> for SignatureSchemeExtensions {
    type Error = Mutter;

    fn try_from(schemes: &[SignatureScheme]) -> Result<Self, Mutter> {
        if !schemes.is_empty() {
            let mut list_sig_alg_ext = Vec::new();
            let mut schemes_dup: Vec<bool> = vec![true, false, false, false];
            for s in schemes.iter() {
                let i = s.sln();
                if schemes_dup[i] { // this is a duplicate entry
                    return Err(Mutter::SignatureSchemeDuplicate)
                } else {
                    schemes_dup[i] = true;
                    list_sig_alg_ext.push(SigAlgExt::new(*s));
                }
            }
            Ok(SignatureSchemeExtensions(list_sig_alg_ext))
        } else {
            Err(Mutter::CipherSuiteLen)
        }
    }
}

#[allow(dead_code)]
impl SignatureSchemeExtensions {
    pub fn schemes(&self) -> &[SigAlgExt] {
        &self.0
    }

    pub fn size(&self) -> usize {
        // the header needs 6 bytes: 2 for extension type + 2 for list size + 2 for data size.
        6 + self.schemes().len() * 2
    }

    pub fn serialize(&self, bytes: &mut [u8], pos: usize) -> usize {
        let len = self.schemes().len() * 2; // each signature scheme takes two bytes.
        // the header needs 6 bytes: 2 for extension type + 2 for list size + 2 for data size.
        if (pos + 6 + len) > bytes.len() {
            0
        } else {
            let mut i = pos;
            (bytes[i], bytes[i + 1]) = (0, 0x0d);
            (bytes[i + 2], bytes[i + 3]) = u16_to_u8_pair((len + 2) as u16);
            (bytes[i + 4], bytes[i + 5]) = u16_to_u8_pair(len as u16);
            i += 6;
            for ext in self.schemes() {
                i += ext.serialize(bytes, i);
            }
            assert_eq!(i - pos, 6 + len);
            6 + len
        }
    }
}

#[cfg(test)]
mod extension_test {
    use crate::def::SupportedGroup;
    use crate::ext::{KeyShare, KeyShareExtensions, PeerType};

    #[test]
    fn test_one_key_share() {
        let x25519_key_ext = KeyShare::try_from((SupportedGroup::X25519 as u16,
                                                 [0u8; 32].as_slice())).unwrap();
        let key_shares: KeyShareExtensions =
            (PeerType::Client, [x25519_key_ext].as_slice()).try_into().unwrap();
        let mut buf = [0; 42];
        let copied = key_shares.serialize(buf.as_mut_slice(), 0);
        assert_eq!(copied, 42);
        assert_eq!(buf[0..2], [0, 0x33]);
        assert_eq!(buf[0..10], [0, 0x33, 0, 38, 0, 36, 00, 0x1d, 00, 32]);
        assert_eq!(buf[10..42], [0].repeat(32));
    }

    #[test]
    fn test_two_key_shares() {
        let x25519_key_ext = KeyShare::try_from((SupportedGroup::X25519 as u16,
                                                 [7u8; 32].as_slice())).unwrap();
        let secp256r1_key_ext = KeyShare::try_from((SupportedGroup::Secp256r1 as u16,
                                                    [19u8; 32].as_slice())).unwrap();
        let key_shares: KeyShareExtensions =
            (PeerType::Client, [x25519_key_ext, secp256r1_key_ext].as_slice()).try_into().unwrap();
        let mut buf = [0; 80];
        let copied = key_shares.serialize(buf.as_mut_slice(), 0);
        assert_eq!(copied, 80);
        assert_eq!(buf[0..2], [0, 0x33]);
        assert_eq!(buf[2..4], [0, 76]);

        assert_eq!(buf[4..10], [0, 36, 00, 0x1d, 00, 32]);
        assert_eq!(buf[10..42], [7].repeat(32));

        assert_eq!(buf[42..48], [0, 36, 00, 0x17, 00, 32]);
        assert_eq!(buf[48..80], [19].repeat(32));
    }
}