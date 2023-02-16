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

/// Like CertD::iter, but returns open `File`s.
///
/// XXX: Use the upstream version once available.
fn lazy_iter<'c>(c: &'c openpgp_cert_d::CertD, base: &'c Path)
                 -> Result<impl Iterator<Item = (String,
                                                 openpgp_cert_d::Tag,
                                                 fs::File)> + 'c> {
    Ok(c.iter_fingerprints()?.filter_map(move |fp| {
        let path = base.join(&fp[..2]).join(&fp[2..]);
        let f = fs::File::open(path).ok()?;
        let tag = f.metadata().ok()?.try_into().ok()?;
        Some((fp, tag, f))
    }))
}

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
        tracer!(TRACE, "CertD::initialize");

        let items = lazy_iter(&self.certd, &self.path)
            .into_iter().flatten() // Folds errors.
            .collect::<Vec<_>>();

        let result: Vec<(openpgp_cert_d::Tag, LazyCert)> = if lazy {
            items.into_iter().filter_map(|(fp, tag, file)| {
                // XXX: Once we have a cached tag, avoid the
                // work if tags match.
                t!("loading {} from overlay", fp);

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
            }).collect()
        } else {
            use rayon::prelude::*;

            // For performance reasons, we read, parse, and
            // canonicalize certs in parallel.
            items.into_par_iter()
                .filter_map(|(fp, tag, file)| {
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
