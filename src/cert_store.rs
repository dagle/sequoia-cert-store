use std::borrow::Cow;
use std::path::Path;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::cert::raw::RawCertParser;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::Result;

use crate::LazyCert;
use crate::store;
use store::Certs;
use store::MergeCerts;
use store::Store;
use store::StoreError;
use store::StoreUpdate;
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
pub struct CertStore<'a> {
    certd: std::result::Result<store::CertD<'a>, store::Certs<'a>>,

    // Read-only backends.
    backends: Vec<(Box<dyn store::Store<'a> + 'a>, AccessMode)>,

    keyserver: Option<Box<dyn store::Store<'a> + 'a>>,
}

impl<'a> CertStore<'a> {
    /// Returns a CertStore, which does not have any configured backends.
    pub fn empty() -> Self {
        CertStore {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        }
    }

    /// Returns a CertStore, which uses the default certificate
    /// directory.
    ///
    /// When a certificate is added or updated, it will be added to or
    /// updated in this certificate store.
    pub fn new() -> Result<Self> {
        Ok(CertStore {
            certd: Ok(store::CertD::open_default()?),
            backends: Vec::new(),
            keyserver: None,
        })
    }

    /// Returns a CertStore, which uses the default certificate
    /// directory in read-only mode.
    pub fn readonly() -> Result<Self> {
        let mut cert_store = CertStore {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        };
        cert_store.add_default_certd()?;
        Ok(cert_store)
    }

    /// Returns a CertStore, which uses the specified certificate
    /// directory.
    ///
    /// When a certificate is added or updated, it will be added to or
    /// updated in this certificate store.
    pub fn open<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        let path = path.as_ref();

        Ok(CertStore {
            certd: Ok(store::CertD::open(path)?),
            backends: Vec::new(),
            keyserver: None,
        })
    }

    /// Returns a CertStore, which uses the specified certificate
    /// directory in read-only mode.
    pub fn open_readonly<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        let path = path.as_ref();

        let mut cert_store = CertStore {
            certd: Err(store::Certs::empty()),
            backends: Vec::new(),
            keyserver: None,
        };
        cert_store.add_certd(path)?;
        Ok(cert_store)
    }

    /// Add the specified backend to the CertStore.
    ///
    /// The backend is added to the collection of read-only backends.
    pub fn add_backend(&mut self, backend: Box<dyn store::Store<'a> + 'a>,
                       mode: AccessMode)
        -> &mut Self
    {
        self.backends.push((backend, mode));
        self
    }

    /// Adds the specified cert-d to the CertStore.
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

    /// Adds the default cert-d to the CertStore.
    ///
    /// The cert-d is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_default_certd(&mut self) -> Result<&mut Self>
    {
        self.add_backend(Box::new(store::CertD::open_default()?),
                         AccessMode::Always);
        Ok(self)
    }

    /// Adds the specified keyring to the CertStore.
    ///
    /// The keyring is added in read-only mode, and its access mode is
    /// set to `AccessMode::Always`.
    pub fn add_keyring<P>(&mut self, path: P) -> Result<&mut Self>
        where P: AsRef<Path>
    {
        self.add_keyrings(std::iter::once(path))?;
        Ok(self)
    }

    /// Adds the specified keyrings to the CertStore.
    ///
    /// The keyrings are added in read-only mode, and their access
    /// mode is set to `AccessMode::Always`.
    pub fn add_keyrings<I, P>(&mut self, filenames: I) -> Result<&mut Self>
    where P: AsRef<Path>,
          I: IntoIterator<Item=P>,
    {
        let mut keyring = Certs::empty();
        let mut error = None;
        for filename in filenames {
            let filename = filename.as_ref();

            let f = std::fs::File::open(filename)
                .with_context(|| format!("Open {:?}", filename))?;
            let parser = RawCertParser::from_reader(f)
                .with_context(|| format!("Parsing {:?}", filename))?;

            for cert in parser {
                match cert {
                    Ok(cert) => {
                        keyring.update(Cow::Owned(cert.into()))
                            .expect("implementation doesn't fail");
                    }
                    Err(err) => {
                        eprint!("Parsing certificate in {:?}: {}",
                                filename, err);
                        error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = error {
            return Err(err).context("Parsing keyrings");
        }

        self.add_backend(
            Box::new(keyring),
            AccessMode::Always);

        Ok(self)
    }

    /// Adds the specified keyserver to the CertStore.
    ///
    /// The keyserver is added in read-only mode, and its access mode
    /// is set to `AccessMode::OnMiss`.
    pub fn add_keyserver(&mut self, url: &str) -> Result<&mut Self>
    {
        self.keyserver = Some(Box::new(store::KeyServer::new(url)?));
        Ok(self)
    }

    /// Adds the specified keyserver to the CertStore.
    ///
    /// The keyserver is added in read-only mode, and its access mode
    /// is set to `AccessMode::OnMiss`.
    ///
    /// A key server is treated specially from other backends: any
    /// results that it returns are written to the cert store (if it
    /// is open in read-write mode).
    pub fn add_keyserver_backend(&mut self, ks: Box<dyn store::Store<'a> + 'a>)
        -> Result<&mut Self>
    {
        self.keyserver = Some(ks);
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

impl<'a> store::Store<'a> for CertStore<'a> {
    fn lookup_by_cert(&self, kh: &KeyHandle)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        let certs = forward!(lookup_by_cert, self, kh, kh)?;
        if certs.is_empty() {
            Err(StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        let certs = forward!(lookup_by_cert_fpr,
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

    fn lookup_by_key(&self, kh: &KeyHandle)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        let certs = forward!(lookup_by_key, self, kh, kh)?;
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

    fn lookup_by_userid(&self, userid: &UserID)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        let certs = forward!(lookup_by_userid, self, userid, userid)?;
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

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let certs = forward!(lookup_by_email, self, email, email)?;
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

    fn lookup_by_email_domain(&self, domain: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        let certs = forward!(lookup_by_email_domain, self, domain, domain)?;
        if certs.is_empty() {
            Err(StoreError::NoMatches(domain.to_string()).into())
        } else {
            Ok(merge(certs))
        }
    }

    fn fingerprints(&self) -> Box<dyn Iterator<Item=Fingerprint> + 'a> {
        let mut certs = Vec::new();

        match self.certd.as_ref() {
            Ok(certd) => certs.extend(certd.fingerprints()),
            Err(in_memory) => certs.extend(in_memory.fingerprints()),
        };

        for (backend, mode) in self.backends.iter() {
            if mode != &AccessMode::Always {
                continue;
            }

            certs.extend(backend.fingerprints());
        }

        certs.sort();
        certs.dedup();

        Box::new(certs.into_iter())
    }

    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        let mut certs = Vec::new();

        match self.certd {
            Ok(ref certd) => certs.extend(certd.certs()),
            Err(ref in_memory) => certs.extend(in_memory.certs()),
        };

        for (backend, mode) in self.backends.iter() {
            if mode != &AccessMode::Always {
                continue;
            }

            certs.extend(backend.certs());
        }

        let certs = merge(certs);

        Box::new(certs.into_iter())
    }

    fn prefetch_all(&mut self) {
        match self.certd.as_mut() {
            Ok(certd) => certd.prefetch_all(),
            Err(in_memory) => in_memory.prefetch_all(),
        };

        for (backend, _mode) in self.backends.iter_mut() {
            backend.prefetch_all();
        }
    }

    fn prefetch_some(&mut self, certs: Vec<KeyHandle>) {
        match self.certd.as_mut() {
            Ok(certd) => certd.prefetch_some(certs.clone()),
            Err(in_memory) => in_memory.prefetch_some(certs.clone()),
        };

        for (backend, _mode) in self.backends.iter_mut() {
            backend.prefetch_some(certs.clone());
        }
    }
}

impl<'a> store::StoreUpdate<'a> for CertStore<'a> {
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        tracer!(TRACE, "CertStore::update_by");
        match self.certd.as_mut() {
            Ok(certd) => {
                t!("Forwarding to underlying certd");
                certd.update_by(cert, merge_strategy)
            }
            Err(in_memory) => {
                t!("Forwarding to underlying in-memory DB");
                in_memory.update_by(cert, merge_strategy)
            }
        }
    }
}

impl<'a> CertStore<'a> {
    /// Flushes any modified certificates to the backing store.
    ///
    /// Currently, this flushes the key server cache to the underlying
    /// cert-d, if any.  All other backends are currently expected to
    /// work in a write-through manner.
    ///
    /// Note: this is called automatically when the `CertStore` is
    /// dropped.
    fn flush(&mut self) -> Result<()> {
        // Sync the key server's cache to the backing store.
        tracer!(TRACE, "CertStore::flush");
        t!("flushing");

        let certd = if let Ok(certd) = self.certd.as_mut() {
            certd
        } else {
            // We don't have a writable backing store so we can't sync
            // anything to it.  We're done.
            t!("no certd, can't sync");
            return Ok(());
        };

        let ks = if let Some(ks) = self.keyserver.as_ref() {
            ks
        } else {
            // We don't have a key server.  There is clearly nothing
            // to sync.
            t!("no keyserver, can't sync");
            return Ok(());
        };

        let mut count = 0;
        let mut result = Ok(());
        for c in ks.certs() {
            count += 1;

            let keyid = c.keyid();
            if let Err(err) = certd.update(c) {
                t!("syncing {} to the cert-d: {}", keyid, err);
                if result.is_ok() {
                    result = Err(err)
                        .with_context(|| {
                            format!("Flushing changes to {} to disk",
                                    keyid)
                        })
                }
            }
        }

        t!("Flushed {} certificates", count);
        result
    }
}

impl<'a> Drop for CertStore<'a> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
