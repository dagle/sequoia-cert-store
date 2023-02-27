use std::borrow::Cow;
use std::cell::RefCell;
use std::cell::Ref;
use std::time::SystemTime;

use once_cell::unsync::OnceCell;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::cert::raw::RawCert;
use openpgp::cert::ValidCert;
use openpgp::packet::Key;
use openpgp::packet::UserID;
use openpgp::packet::key;
use openpgp::policy::Policy;
use openpgp::serialize::SerializeInto;

use super::TRACE;

#[derive(Clone)]
pub struct LazyCert<'a> {
    // Exactly one of raw and cert are ever alive.  Ideally, we'd put
    // them in an enum.  To do that, the enum would have to be behind
    // a `RefCell`, but then we couldn't return bare references to the
    // `Cert`.
    raw: RefCell<Option<RawCert<'a>>>,
    cert: OnceCell<Cow<'a, Cert>>,
}

impl<'a> LazyCert<'a> {
    /// Creates a `LazyCert` from a `Cert`.
    pub fn from_cert(cert: Cert) -> Self {
        tracer!(TRACE, "LazyCert::from_cert");
        t!("Adding a parsed cert: {}", cert.fingerprint());

        Self {
            raw: RefCell::new(None),
            cert: OnceCell::with_value(Cow::Owned(cert)),
        }
    }

    /// Creates a `LazyCert` from a `&Cert`.
    pub fn from_cert_ref(cert: &'a Cert) -> Self {
        tracer!(TRACE, "LazyCert::from_cert_ref");
        t!("Adding a parsed cert: {}", cert.fingerprint());

        Self {
            raw: RefCell::new(None),
            cert: OnceCell::with_value(Cow::Borrowed(cert)),
        }
    }

    /// Creates a `LazyCert` from a `RawCert`.
    pub fn from_raw_cert(raw: RawCert<'a>) -> Self {
        Self {
            raw: RefCell::new(Some(raw)),
            cert: OnceCell::new(),
        }
    }

    /// Returns a reference to the raw cert, if the certificate hasn't
    /// been parsed yet.
    pub fn raw_cert(&self) -> Ref<Option<RawCert<'a>>> {
        self.raw.borrow()
    }

    /// Returns the certificate's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        if let Some(cert) = self.cert.get() {
            cert.fingerprint()
        } else if let Some(raw) = &*self.raw.borrow() {
            raw.fingerprint()
        } else {
            unreachable!("cert or raw must be set")
        }
    }

    /// Returns the certificate's Key ID.
    pub fn keyid(&self) -> KeyID {
        KeyID::from(self.fingerprint())
    }

    /// Returns the certificate's Key Handle.
    pub fn key_handle(&self) -> KeyHandle {
        KeyHandle::from(self.fingerprint())
    }

    /// Returns the user ids.
    pub fn userids(&self)
        -> impl Iterator<Item=UserID> + '_
    {
        if let Some(cert) = self.cert.get() {
            Box::new(cert.userids().map(|ua| ua.userid().clone()))
                as Box<dyn Iterator<Item=UserID> + '_>
        } else if let Some(raw) = &*self.raw.borrow() {
            Box::new(
                raw.userids()
                    // This is rather unsatisfying, but due to
                    // lifetimes...
                    .collect::<Vec<UserID>>()
                    .into_iter())
                as Box<dyn Iterator<Item=UserID> + '_>
        } else {
            unreachable!("cert or raw must be set")
        }
    }

    /// Returns the keys.
    pub fn keys(&self)
        -> impl Iterator<Item=Key<key::PublicParts, key::UnspecifiedRole>> + '_
    {
        if let Some(cert) = self.cert.get() {
            Box::new(cert.keys().map(|ka| ka.key().clone()))
                as Box<dyn Iterator<Item=Key<_, _>> + '_>
        } else if let Some(raw) = &*self.raw.borrow() {
            Box::new(
                raw
                    .keys()
                    // This is rather unsatisfying, but due to
                    // lifetimes...
                    .collect::<Vec<Key<_, _>>>()
                    .into_iter())
                as Box<dyn Iterator<Item=Key<_, _>> + '_>
        } else {
            unreachable!("cert or raw must be set")
        }
    }

    /// Returns the primary key.
    pub fn primary_key(&self) -> Key<key::PublicParts, key::PrimaryRole> {
        self.keys().next().expect("have a primary key").role_into_primary()
    }

    /// Returns the subkeys.
    pub fn subkeys<'b>(&'b self)
        -> impl Iterator<Item=Key<key::PublicParts,
                                  key::UnspecifiedRole>> + 'b
    {
        self.keys().skip(1)
    }

    /// Returns a reference to the parsed certificate.
    ///
    /// If the `LazyCert` is not yet parsed, parses now.
    pub fn to_cert(&self) -> Result<&Cert> {
        tracer!(TRACE, "LazyCert::to_cert");

        if let Some(cert) = self.cert.get() {
            return Ok(cert);
        }

        let mut clear = false;
        if let Some(raw) = &*self.raw.borrow() {
            t!("Resolving {}", raw.fingerprint());
            match Cert::try_from(raw) {
                Ok(cert) => {
                    self.cert.set(Cow::Owned(cert))
                        .expect("just checked that it was empty");
                    clear = true;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        if clear {
            *self.raw.borrow_mut() = None;
        }

        if let Some(cert) = self.cert.get() {
            return Ok(cert);
        } else {
            unreachable!("cert or raw must be set")
        }
    }

    /// Returns the parsed certificate.
    ///
    /// If the `LazyCert` is not yet parsed, parses now.
    pub fn into_cert(self) -> Result<Cert> {
        let _ = self.to_cert()?;
        Ok(self.cert.into_inner().expect("valid").into_owned())
    }

    /// Returns the parsed certificate.
    ///
    /// If the `LazyCert` is not yet parsed, parses now.
    pub fn as_cert(&self) -> Result<Cert> {
        let _ = self.to_cert()?;
        Ok(self.cert.get().expect("valid").clone().into_owned())
    }

    pub fn with_policy<'b, T>(&'b self, policy: &'b dyn Policy, time: T)
        -> Result<ValidCert<'b>>
    where
        T: Into<Option<SystemTime>>,
    {
        let cert = self.to_cert()?;
        cert.with_policy(policy, time)
    }
}

impl<'a> From<Cert> for LazyCert<'a> {
    fn from(cert: Cert) -> Self {
        LazyCert::from_cert(cert)
    }
}

impl<'a> From<RawCert<'a>> for LazyCert<'a> {
    fn from(cert: RawCert<'a>) -> Self {
        LazyCert::from_raw_cert(cert)
    }
}

// We can't implement openpgp::serialize::Marshal, because it is
// sealed.  So we fake what is used :/.
impl<'a> LazyCert<'a> {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        if let Some(raw) = &*self.raw.borrow() {
            Ok(raw.as_bytes().to_vec())
        } else if let Some(cert) = self.cert.get() {
            Ok(cert.to_vec()?)
        } else {
            unreachable!("raw or cert must be set");
        }
    }

    pub fn export(&self, o: &mut dyn std::io::Write) -> Result<()> {
        use openpgp::serialize::Marshal;

        // We need to strip any local signatures.  If we have a
        // RawCert, we could try to figure out if there are any local
        // signatures to vaoid parsing and reserializing, but that is
        // error prone.
        let cert = self.to_cert()?;
        Ok(cert.export(o)?)
    }
}
