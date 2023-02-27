use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map;
use std::fs;
use std::rc::Rc;
use std::path::Path;
use std::path::PathBuf;
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::cert::raw::RawCertParser;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

use openpgp_cert_d as cert_d;

use crate::LazyCert;
use crate::print_error_chain;
use crate::store::Store;
use crate::store::StoreError;
use crate::store::StoreUpdate;
use crate::store::UserIDIndex;
use crate::store::UserIDQueryParams;

use crate::TRACE;

pub struct CertD<'a> {
    certd: cert_d::CertD,
    path: PathBuf,

    by_cert_fpr: HashMap<Fingerprint, Rc<LazyCert<'a>>>,
    by_cert_keyid: HashMap<KeyID, Vec<Rc<LazyCert<'a>>>>,

    // It is possible that the same key can be bound to multiple
    // certificates.
    by_subkey_fpr: HashMap<Fingerprint, Vec<Rc<LazyCert<'a>>>>,
    by_subkey_keyid: HashMap<KeyID, Vec<Rc<LazyCert<'a>>>>,

    userid_index: UserIDIndex,
}

impl<'a> CertD<'a> {
    /// Returns the canonicalized path.
    ///
    /// If path is `None`, then returns the default location.
    ///
    /// XXX: This (or an equivalent mechnaism) should be provided by
    /// cert-d.
    fn path(path: Option<&Path>) -> Result<PathBuf>
    {
        Ok(path
            .map(|path| path.to_owned())
            .or_else(|| std::env::var_os("PGP_CERT_D").map(Into::into))
            .unwrap_or_else(|| {
                dirs::data_dir()
                    .expect("Unsupported platform")
                    .join("pgp.cert.d")
            }))
    }

    /// Opens the default cert-d for reading and writing.
    pub fn open_default() -> Result<Self>
    {
        let path = Self::path(None)?;
        Self::open(path)
    }

    /// Opens a cert-d for reading and writing.
    pub fn open<P>(path: P) -> Result<Self>
        where P: AsRef<Path>,
    {
        tracer!(TRACE, "CertD::open");

        let path = path.as_ref();
        let path = Self::path(Some(path))?;
        t!("loading cert-d {:?}", path);

        let certd = openpgp_cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        let mut certd = Self {
            certd,
            path,
            by_cert_fpr: HashMap::default(),
            by_cert_keyid: HashMap::default(),
            by_subkey_fpr: HashMap::default(),
            by_subkey_keyid: HashMap::default(),

            userid_index: UserIDIndex::new(),
        };

        certd.initialize(true)?;
        Ok(certd)
    }

    /// Returns a reference to the certd, if there is one.
    pub fn certd(&self) -> &openpgp_cert_d::CertD {
        &self.certd
    }

    /// Returns a mutable reference to the certd, if there
    /// is one.
    pub fn certd_mut(&mut self) -> &mut openpgp_cert_d::CertD {
        &mut self.certd
    }

    /// Inserts the given cert into the in-memory database.
    fn index<C>(&mut self, _tag: Option<openpgp_cert_d::Tag>, cert: C)
        where C: Into<LazyCert<'a>>
    {
        tracer!(TRACE, "CertD::index");
        let cert = cert.into();
        t!("Inserting {} into the in-core caches", cert.fingerprint());
        let rccert = Rc::new(cert);

        // Check if the certificate is already present.  If so, we are
        // reupdating so avoid duplicates.

        let fpr = rccert.fingerprint();
        let update = if let Some(_old)
            = self.by_cert_fpr.insert(fpr.clone(), rccert.clone())
        {
            // This is an update.

            // XXX: Remove any keys or user ids that were removed.

            true
        } else {
            false
        };

        match self.by_cert_keyid.entry(KeyID::from(&fpr)) {
            hash_map::Entry::Occupied(mut oe) => {
                let certs = oe.get_mut();
                if ! update
                    || ! certs.iter().any(|c| c.fingerprint() == fpr)
                {
                    certs.push(rccert.clone());
                }
            }
            hash_map::Entry::Vacant(ve) => {
                ve.insert(vec![ rccert.clone() ]);
            }
        }

        for subkey in rccert.subkeys() {
            let fpr = subkey.fingerprint();

            match self.by_subkey_fpr.entry(fpr.clone()) {
                hash_map::Entry::Occupied(mut oe) => {
                    let certs = oe.get_mut();
                    if ! update
                        || ! certs.iter().any(|c| c.fingerprint() == fpr)
                    {
                        certs.push(rccert.clone());
                    }
                }
                hash_map::Entry::Vacant(ve) => {
                    ve.insert(vec![ rccert.clone() ]);
                }
            }

            match self.by_subkey_keyid.entry(KeyID::from(&fpr)) {
                hash_map::Entry::Occupied(mut oe) => {
                    let certs = oe.get_mut();
                    if ! update
                        || ! certs.iter().any(|c| c.fingerprint() == fpr)
                    {
                        certs.push(rccert.clone());
                    }
                }
                hash_map::Entry::Vacant(ve) => {
                    ve.insert(vec![ rccert.clone() ]);
                }
            }
        }

        self.userid_index.insert(&fpr, rccert.userids());
    }

    // Initialize a certd by reading the entries and populating the
    // index.
    fn initialize(&mut self, lazy: bool) -> Result<()>
    {
        use rayon::prelude::*;

        tracer!(TRACE, "CertD::initialize");

        let items = self.certd.iter_fingerprints()?;

        let open = |fp: String| -> Option<(String, _, _)> {
            let path = self.path.join(&fp[..2]).join(&fp[2..]);

            let f = match fs::File::open(&path) {
                Ok(f) => f,
                Err(err) => {
                    t!("Reading {:?}: {}", path, err);
                    return None;
                }
            };
            let metadata = match f.metadata() {
                Ok(f) => f,
                Err(err) => {
                    t!("Stating entry {:?}: {}", path, err);
                    return None;
                }
            };
            match openpgp_cert_d::Tag::try_from(metadata) {
                Ok(tag) => Some((fp, tag, f)),
                Err(err) => {
                    t!("Getting tag for entry {:?}: {}", path, err);
                    None
                }
            }
        };

        let result: Vec<(openpgp_cert_d::Tag, LazyCert)> = if lazy {
            items.collect::<Vec<_>>().into_par_iter()
                .filter_map(|fp| {
                    // XXX: Once we have a cached tag, avoid the
                    // work if tags match.
                    t!("loading {} from overlay", fp);

                    let (fp, tag, file) = open(fp)?;

                    let mut parser = match RawCertParser::from_reader(file) {
                        Ok(parser) => parser,
                        Err(err) => {
                            let err = anyhow::Error::from(err).context(format!(
                                "While reading {:?} from the certd {:?}",
                                fp, self.path));
                            print_error_chain(&err);
                            return None;
                        }
                    };

                    match parser.next() {
                        Some(Ok(cert)) => Some((tag, LazyCert::from(cert))),
                        Some(Err(err)) => {
                            let err = anyhow::Error::from(err).context(format!(
                                "While parsing {:?} from the certd {:?}",
                                fp, self.path));
                            print_error_chain(&err);
                            None
                        }
                        None => {
                            let err = anyhow::anyhow!(format!(
                                "While parsing {:?} from the certd {:?}: empty file",
                                fp, self.path));
                            print_error_chain(&err);
                            None
                        }
                    }
                })
                .collect()
        } else {
            // For performance reasons, we read, parse, and
            // canonicalize certs in parallel.
            items.collect::<Vec<_>>().into_par_iter()
                .filter_map(|fp| {
                    let (fp, tag, file) = open(fp)?;

                    // XXX: Once we have a cached tag and
                    // presumably a Sync index, avoid the work if
                    // tags match.
                    t!("loading {} from overlay", fp);
                    match Cert::from_reader(file) {
                        Ok(cert) => Some((tag, LazyCert::from(cert))),
                        Err(err) => {
                            let err = anyhow::Error::from(err).context(format!(
                                "While parsing {:?} from the certd {:?}",
                                fp, self.path));
                            print_error_chain(&err);
                            None
                        }
                    }
                })
                .collect()
        };

        for (tag, cert) in result {
            self.index(Some(tag), cert)
        }

        Ok(())
    }
}

impl<'a> Store<'a> for CertD<'a> {
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "CertD::by_cert");
        t!("{}", kh);

        match kh {
            KeyHandle::Fingerprint(fpr) =>
                self.by_cert_fpr.get(fpr)
                    .ok_or_else(|| StoreError::NotFound(kh.clone()).into())
                    .map(|cert| vec![ Cow::Borrowed(cert.as_ref()) ]),
            KeyHandle::KeyID(id) =>
                self.by_cert_keyid.get(id)
                    .ok_or_else(|| StoreError::NotFound(kh.clone()).into())
                    .map(|certs| {
                        certs.iter()
                            .map(|cert| {
                                Cow::Borrowed(cert.as_ref())
                            })
                            .collect()
                    }),
        }
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "CertD::by_cert");
        t!("{}", kh);

        let mut by_cert: Vec<Cow<LazyCert>> = self.by_cert(kh)
            .or_else(|err| {
                if let Some(StoreError::NotFound(_))
                    = err.downcast_ref::<StoreError>()
                {
                    Ok(Vec::new())
                } else {
                    Err(err)
                }
            })?;

        let by_subkey: Option<&Vec<Rc<LazyCert>>> = match kh {
            KeyHandle::Fingerprint(fpr) => self.by_subkey_fpr.get(fpr),
            KeyHandle::KeyID(id) => self.by_subkey_keyid.get(id),
        };
        let mut by_subkey = if let Some(certs) = by_subkey {
            certs.iter().map(|cert| Cow::Borrowed(cert.as_ref()))
                .collect::<Vec<Cow<LazyCert>>>()
        } else {
            Vec::new()
        };

        // Combine them.  Avoid reallocating if possible.
        let mut certs = if by_subkey.capacity() >= by_cert.len() + by_subkey.len() {
            by_subkey.append(&mut by_cert);
            by_subkey
        } else {
            by_cert.append(&mut by_subkey);
            by_cert
        };

        // We could have get the same certificate multiple times if a
        // key is a primary key and a subkey for the same certificate.
        // To handle this, we need to deduplicate the results.
        certs.sort_by_key(|c| c.fingerprint());
        certs.dedup_by_key(|c| c.fingerprint());

        if certs.is_empty() {
            Err(StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(certs)
        }
    }

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        Box::new(self.by_cert_fpr.keys().cloned())
    }

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        Box::new(self.by_cert_fpr
                 .values()
                 .map(|c| Cow::Borrowed(c.as_ref())))
    }

    fn select_userid(&self, params: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        tracer!(true, "CertD::select_userid");
        t!("params: {:?}, pattern: {:?}", params, pattern);

        let matches = self.userid_index.select_userid(params, pattern)?;

        let matches = matches
            .into_iter()
            .map(|fpr| {
                self.by_cert_fpr(&fpr).expect("indexed")
            })
            .collect();

        Ok(matches)
    }

    fn precompute(&self) {
    }
}

impl<'a> StoreUpdate<'a> for CertD<'a> {
    fn insert_lazy_cert(&mut self, cert: LazyCert<'a>) -> Result<()> {
        self.certd.insert(cert.to_vec()?.into(), |new, old| {
            if let Some(old) = old {
                Ok(Cert::from_bytes(&old)?
                   .merge_public(Cert::from_bytes(&new)?)?
                   .to_vec()?.into())
            } else {
                Ok(new)
            }
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context;

    use openpgp::packet::UserID;
    use openpgp::serialize::Serialize;

    // Make sure that we can read a huge cert-d.  Specifically, the
    // typical file descriptor limit is 1024.  Make sure we can
    // initialize and iterate over a cert-d with a few more entries
    // than that.
    #[test]
    fn huge_cert_d() -> Result<()> {
        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        // Generate some certificates and write them to a cert-d using
        // the low-level interface.
        const N: usize = 1050;

        let mut certs = Vec::new();
        let mut certs_fpr = Vec::new();
        let mut subkeys_fpr = Vec::new();
        let mut userids = Vec::new();

        for i in 0..N {
            let userid = format!("<{}@example.org>", i);

            let (cert, _rev) = CertBuilder::new()
                .set_cipher_suite(CipherSuite::Cv25519)
                .add_userid(UserID::from(&userid[..]))
                .add_storage_encryption_subkey()
                .generate()
                .expect("ok");

            certs_fpr.push(cert.fingerprint());
            subkeys_fpr.extend(cert.keys().subkeys().map(|ka| ka.fingerprint()));
            userids.push(userid);

            let mut bytes = Vec::new();
            cert.serialize(&mut bytes).expect("can serialize to a vec");
            certd
                .insert(bytes.into_boxed_slice(), |new, disk| {
                    assert!(disk.is_none());

                    Ok(new)
                })
                .with_context(|| {
                    format!("{:?} ({})", path, cert.fingerprint())
                })
                .expect("can insert");

            certs.push(cert);
        }

        // One subkey per certificate.
        assert_eq!(certs_fpr.len(), subkeys_fpr.len());

        certs_fpr.sort();

        // Open the cert-d and make sure we can read what we wrote via
        // the low-level interface.
        let certd = CertD::open(&path).expect("exists");

        // Test Store::iter.  In particular, make sure we get
        // everything back.
        let mut certs_read = certd.iter().collect::<Vec<_>>();
        assert_eq!(
            certs_read.len(), certs.len(),
            "Looks like you're exhausting the available file descriptors");

        certs_read.sort_by_key(|c| c.fingerprint());
        let certs_read_fpr
            = certs_read.iter().map(|c| c.fingerprint()).collect::<Vec<_>>();
        assert_eq!(certs_fpr, certs_read_fpr);

        // Test Store::by_cert.
        for cert in certs.iter() {
            let certs_read = certd.by_cert(&cert.key_handle()).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");
            assert_eq!(&cert_read, cert);
        }

        for subkey in subkeys_fpr.iter() {
            let kh = KeyHandle::from(subkey.clone());
            match certd.by_cert(&kh) {
                Ok(certs) => panic!("Expected nothing, got {} certs", certs.len()),
                Err(err) => {
                    assert_eq!(err.downcast_ref::<StoreError>(),
                               Some(&StoreError::NotFound(KeyHandle::from(kh))))
                }
            }
        }

        // Test Store::by_key.
        for fpr in certs.iter().map(|cert| cert.fingerprint())
            .chain(subkeys_fpr.iter().cloned())
        {
            let certs_read
                = certd.by_key(&KeyHandle::from(fpr.clone())).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");

            assert!(cert_read.keys().any(|k| k.fingerprint() == fpr));
        }

        // Test Store::by_userid.
        for userid in userids.iter() {
            let userid = UserID::from(&userid[..]);

            let certs_read
                = certd.by_userid(&userid).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");

            assert!(cert_read.userids().any(|u| u.userid() == &userid));
        }

        Ok(())
    }
}
