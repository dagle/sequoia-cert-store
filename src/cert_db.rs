use std::any::Any;
use std::borrow::Cow;
use std::path::Path;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::UserID;

use crate::LazyCert;
use crate::store;
use store::StoreError;
use store::UserIDQueryParams;

use crate::TRACE;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessMode {
    Always,
    OnMiss,
}

/// A unified interface to multiple certificate stores.
///
/// When a certificate is looked up, the certificate is looked up in
/// the primary cert-d, if any, and all the backends whose access mode
/// is `AccessMode::Always`.  The results are merged and returned.  If
/// no certificate is found, then the look up is also tried on the
/// backends whose access mode is `AccessMode::OnMiss`.  Finally, if a
/// key server is configured, the key server is tried.
///
/// In general, results are preferred to errors.  That is, if a
/// backend returns a positive result, and another backend returns an
/// error, the error is ignored, even if it is something other than
/// [`StoreError::NotFound`].
///
/// Results from the key server are either cached
pub struct CertDB<'a> {
    certd: std::result::Result<store::CertD<'a>, store::Certs<'a>>,

    // Read-only backends.
    backends: Vec<(Box<dyn store::Store<'a> + 'a>, AccessMode)>,

    keyserver: Option<store::KeyServer<'a>>,
}

impl<'a> CertDB<'a> {
    /// Returns a CertDB, which does not have any configured backends.
    pub fn empty() -> Self {
        CertDB {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        }
    }

    /// Returns a CertDB, which uses the default certificate
    /// directory.
    ///
    /// When a certificate is added or updated, it will be added to or
    /// updated in this certificate store.
    pub fn new() -> Result<Self> {
        Ok(CertDB {
            certd: Ok(store::CertD::open_default()?),
            backends: Vec::new(),
            keyserver: None,
        })
    }

    /// Returns a CertDB, which uses the default certificate
    /// directory in read-only mode.
    pub fn readonly() -> Result<Self> {
        let mut certdb = CertDB {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        };
        certdb.add_default_certd()?;
        Ok(certdb)
    }

    /// Returns a CertDB, which uses the specified certificate
    /// directory.
    ///
    /// When a certificate is added or updated, it will be added to or
    /// updated in this certificate store.
    pub fn open<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        let path = path.as_ref();

        Ok(CertDB {
            certd: Ok(store::CertD::open(path)?),
            backends: Vec::new(),
            keyserver: None,
        })
    }

    /// Returns a CertDB, which uses the specified certificate
    /// directory in read-only mode.
    pub fn open_readonly<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        let path = path.as_ref();

        let mut certdb = CertDB {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        };
        certdb.add_certd(path)?;
        Ok(certdb)
    }

    /// Add the specified backend to the CertDB.
    ///
    /// The backend is added to the collection of read-only backends.
    pub fn add_backend(&mut self, backend: Box<dyn store::Store<'a> + 'a>,
                       mode: AccessMode)
        -> &mut Self
    {
        self.backends.push((backend, mode));
        self
    }

    /// Adds the specified cert-d to the CertDB.
    ///
    /// The cert-d is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_certd<P>(&mut self, path: P) -> Result<&mut Self>
        where P: AsRef<Path>
    {
        let path = path.as_ref();
        self.add_backend(Box::new(store::CertD::open(path)?),
                         AccessMode::Always);
        Ok(self)
    }

    /// Adds the default cert-d to the CertDB.
    ///
    /// The cert-d is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_default_certd(&mut self) -> Result<&mut Self>
    {
        self.add_backend(Box::new(store::CertD::open_default()?),
                         AccessMode::Always);
        Ok(self)
    }

    /// Adds the specified keyring to the CertDB.
    ///
    /// The keyring is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_keyring<P>(&mut self, path: P) -> Result<&mut Self>
        where P: AsRef<Path>
    {
        let _path = path.as_ref();
        Ok(self)
    }

    /// Adds the specified keybox to the CertDB.
    ///
    /// The keybox is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_keybox<P>(&mut self, path: P) -> Result<&mut Self>
        where P: AsRef<Path>
    {
        let _path = path.as_ref();
        Ok(self)
    }

    /// Adds the specified keyserver to the CertDB.
    ///
    /// The keyserver is added in read-only mode, and its access mode
    /// is set to `AccessMode::OnMiss`.
    pub fn add_keyserver(&mut self, _url: String) -> Result<&mut Self>
    {
        Ok(self)
    }

    /// Returns a reference to the certd store, if there is one.
    pub fn certd(&self) -> Option<&store::CertD<'a>> {
        self.certd.as_ref().ok()
    }

    /// Returns a mutable reference to the certd store, if there
    /// is one.
    pub fn certd_mut(&mut self) -> Option<&mut store::CertD<'a>> {
        self.certd.as_mut().ok()
    }
}

macro_rules! forward {
    ( $method:ident, append:$to_vec:expr, $self:expr, $term:expr, $($args:ident),* ) => {{
        tracer!(TRACE, format!("{}({})", stringify!($method), $term));

        let mut certs = Vec::new();
        let mut err = None;

        match &$self.certd {
            Ok(certd) => {
                match certd.$method($($args),*) {
                    Err(err2) => {
                        if let Some(StoreError::NotFound(_))
                            = err2.downcast_ref::<StoreError>()
                        {
                            // Ignore NotFound.
                            t!("certd returned nothing");
                        } else {
                            t!("certd returned: {}", err2);
                            err = Some(err2)
                        }
                    }
                    Ok(c) => {
                        let mut c = $to_vec(c);
                        t!("certd returned {}",
                           c.iter()
                               .map(|cert| cert.fingerprint().to_string())
                               .collect::<Vec<String>>()
                               .join(", "));
                        certs.append(&mut c)
                    }
                }
            }
            Err(in_memory) => {
                match in_memory.$method($($args),*) {
                    Err(err2) => {
                        if let Some(StoreError::NotFound(_))
                            = err2.downcast_ref::<StoreError>()
                        {
                            // Ignore NotFound.
                            t!("in-memory returned nothing");
                        } else {
                            t!("in-memory returned: {}", err2);
                            err = Some(err2)
                        }
                    }
                    Ok(c) => {
                        let mut c = $to_vec(c);
                        t!("in-memory returned {}",
                           c.iter()
                               .map(|cert| cert.fingerprint().to_string())
                               .collect::<Vec<String>>()
                               .join(", "));
                        certs.append(&mut c)
                    }
                }
            }
        }

        for mode in [AccessMode::Always, AccessMode::OnMiss] {
            for (backend, m) in $self.backends.iter() {
                if &mode != m {
                    continue;
                }

                match backend.$method($($args),*) {
                    Err(err2) => {
                        if let Some(StoreError::NotFound(_))
                            = err2.downcast_ref::<StoreError>()
                        {
                            // Ignore NotFound.
                            t!("backend returned nothing");
                        } else {
                            t!("backend returned: {}", err2);
                            err = Some(err2)
                        }
                    }
                    Ok(c) => {
                        let mut c = $to_vec(c);
                        t!("backend returned {}",
                           c.iter()
                               .map(|cert| cert.fingerprint().to_string())
                               .collect::<Vec<String>>()
                               .join(", "));
                        certs.append(&mut c)
                    }
                }
            }

            if mode == AccessMode::Always && ! certs.is_empty() {
                break;
            }
        }

        if certs.is_empty() {
            if let Some(ks) = $self.keyserver.as_ref() {
                if let Ok(c) = ks.$method($($args),*) {
                    certs = $to_vec(c);
                    t!("keyserver returned {}",
                       certs.iter()
                           .map(|cert| cert.fingerprint().to_string())
                           .collect::<Vec<String>>()
                           .join(", "));
                }
            }
        }

        if certs.is_empty() {
            if let Some(err) = err {
                t!("query failed: {}", err);
                Err(err)
            } else {
                t!("query returned nothing");
                Ok(certs)
            }
        } else {
            t!("query returned {}",
               certs.iter()
                   .map(|cert| cert.fingerprint().to_string())
                   .collect::<Vec<String>>()
                   .join(", "));
            Ok(certs)
        }
    }};

    ( $method:ident, $self:expr, $($args:ident),* ) => {{
        forward!($method,
                 append:|c| c,
                 $self,
                 $($args),*)
    }}
}

fn merge<'a, 'b>(mut certs: Vec<Cow<'b, LazyCert<'a>>>)
    -> Vec<Cow<'b, LazyCert<'a>>>
{
    certs.sort_by_key(|cert| cert.fingerprint());
    certs.dedup_by(|a, b| {
        // If this returns true, a is dropped.  So merge into b.
        if a.fingerprint() == b.fingerprint() {
            if let Ok(a2) = a.to_cert() {
                if let Ok(b2) = b.to_cert() {
                    *b = Cow::Owned(LazyCert::from(
                        b2.clone()
                            .merge_public(a2.clone())
                            .expect("Same certificate")));
                } else {
                    // b is invalid, but a is valid.  Just keep a.
                    *b = Cow::Owned(LazyCert::from(a2.clone()));
                }
            } else {
                // a is invalid.  By returning true, we drop a.
                // That's what we want.
            }
            true
        } else {
            false
        }
    });
    certs
}

impl<'a> store::Store<'a> for CertDB<'a> {
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(by_cert, self, kh, kh)?;
        if certs.is_empty() {
            Err(StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn by_cert_fpr(&self, fingerprint: &Fingerprint) -> Result<Cow<LazyCert<'a>>>
    {
        let certs = forward!(by_cert_fpr,
                             append:|c| vec![c],
                             self, fingerprint, fingerprint)?;
        // There may be multiple variants.  Merge them.
        let certs = merge(certs);
        assert!(certs.len() <= 1);
        if let Some(cert) = certs.into_iter().next() {
            Ok(cert)
        } else {
            Err(StoreError::NotFound(
                KeyHandle::from(fingerprint.clone())).into())
        }
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(by_key, self, kh, kh)?;
        if certs.is_empty() {
            Err(StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        let certs = forward!(select_userid, self, pattern, query, pattern)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(pattern.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(by_userid, self, userid, userid)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(
                String::from_utf8_lossy(userid.value()).to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(grep_userid, self, pattern, pattern)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(pattern.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(by_email, self, email, email)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(email.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(grep_email, self, pattern, pattern)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(pattern.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(by_email_domain, self, domain, domain)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(domain.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn list(&self) -> Box<dyn Iterator<Item=Fingerprint> + 'a> {
        let mut certs = Vec::new();

        match self.certd.as_ref() {
            Ok(certd) => certs.extend(certd.list()),
            Err(in_memory) => certs.extend(in_memory.list()),
        };

        for (backend, mode) in self.backends.iter() {
            if mode != &AccessMode::Always {
                continue;
            }

            certs.extend(backend.list());
        }

        certs.sort();
        certs.dedup();

        Box::new(certs.into_iter())
    }

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        let mut certs = Vec::new();

        match self.certd {
            Ok(ref certd) => certs.extend(certd.iter()),
            Err(ref in_memory) => certs.extend(in_memory.iter()),
        };

        for (backend, mode) in self.backends.iter() {
            if mode != &AccessMode::Always {
                continue;
            }

            certs.extend(backend.iter());
        }

        let certs = merge(certs);

        Box::new(certs.into_iter())
    }

    fn precompute(&self) {
        match self.certd.as_ref() {
            Ok(certd) => certd.precompute(),
            Err(in_memory) => in_memory.precompute(),
        };

        for (backend, _mode) in self.backends.iter() {
            backend.precompute();
        }
    }
}

impl<'a> store::StoreUpdate<'a> for CertDB<'a> {
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      cookie: Option<&mut dyn Any>,
                      merge_strategy:
                      for <'b, 'rb, 'c> fn(Cow<'ra, LazyCert<'a>>,
                                           Option<Cow<'rb, LazyCert<'b>>>,
                                           Option<&'c mut dyn Any>)
                                           -> Result<Cow<'ra, LazyCert<'a>>>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        match self.certd.as_mut() {
            Ok(certd) => {
                certd.update_by(cert, cookie, merge_strategy)
            }
            Err(in_memory) => {
                in_memory.update_by(cert, cookie, merge_strategy)
            }
        }
    }
}
