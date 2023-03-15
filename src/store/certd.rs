use std::borrow::Cow;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::raw::RawCertParser;
use openpgp::cert::prelude::*;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

use openpgp_cert_d as cert_d;

use crate::LazyCert;
use crate::store::Certs;
use crate::store::MergeCerts;
use crate::store::Store;
use crate::store::StoreUpdate;
use crate::store::UserIDQueryParams;

use crate::TRACE;

pub struct CertD<'a> {
    certd: cert_d::CertD,
    path: PathBuf,

    certs: Certs<'a>,
}

impl<'a> CertD<'a> {
    /// Returns the canonicalized path.
    ///
    /// If path is `None`, then returns the default location.
    ///
    /// XXX: This (or an equivalent mechanism) should be provided by
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
                t!("While opening the certd {:?}: {}", path, err);
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                err
            })?;

        let mut certd = Self {
            certd,
            path,
            certs: Certs::empty(),
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

        let result: Vec<(String, openpgp_cert_d::Tag, LazyCert)> = if lazy {
            items.collect::<Vec<_>>().into_par_iter()
                .filter_map(|fp| {
                    // XXX: Once we have a cached tag, avoid the
                    // work if tags match.
                    t!("loading {} from overlay", fp);

                    let (fp, tag, file) = open(fp)?;

                    let mut parser = match RawCertParser::from_reader(file) {
                        Ok(parser) => parser,
                        Err(err) => {
                            t!("While reading {:?} from the certd {:?}: {}",
                               fp, self.path, err);
                            return None;
                        }
                    };

                    match parser.next() {
                        Some(Ok(cert)) => Some((fp, tag, LazyCert::from(cert))),
                        Some(Err(err)) => {
                            t!("While parsing {:?} from the certd {:?}: {}",
                                fp, self.path, err);
                            None
                        }
                        None => {
                            t!("While parsing {:?} from the certd {:?}: empty file",
                                fp, self.path);
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
                        Ok(cert) => Some((fp, tag, LazyCert::from(cert))),
                        Err(err) => {
                            t!("While parsing {:?} from the certd {:?}: {}",
                               fp, self.path, err);
                            None
                        }
                    }
                })
                .collect()
        };

        for (fp, _tag, cert) in result {
            if let Err(err) = self.certs.update(Cow::Owned(cert)) {
                // This is an in-memory index and updates doesn't
                // fail.  Nevertheless, we don't panic.
                t!("Error inserting {} into the in-memory index: {}",
                   fp, err);
            }
        }

        Ok(())
    }
}

impl<'a> Store<'a> for CertD<'a> {
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        self.certs.lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.lookup_by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        self.certs.select_userid(query, pattern)
    }

    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.lookup_by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.grep_userid(pattern)
    }

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.lookup_by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.grep_email(pattern)
    }

    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.certs.lookup_by_email_domain(domain)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        self.certs.fingerprints()
    }

    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        self.certs.certs()
    }

    fn prefetch_all(&mut self) {
        self.certs.prefetch_all()
    }

    fn prefetch_some(&mut self, certs: Vec<KeyHandle>) {
        self.certs.prefetch_some(certs)
    }
}

impl<'a> StoreUpdate<'a> for CertD<'a> {
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        tracer!(TRACE, "CertD::update_by");
        t!("Inserting {}", cert.fingerprint());

        // This is slightly annoying: cert-d expects bytes.  But
        // serializing cert is a complete waste if we have to merge
        // the certificate with another one.  cert-d actually only
        // needs the primary key, which it uses to derive the
        // fingerprint, so, we only serialize that.
        let fpr = cert.fingerprint();
        let cert_stub = Cert::from_packets(
            std::iter::once(Packet::from(cert.primary_key())))?
            .to_vec()?
            .into_boxed_slice();

        let mut merged = None;
        self.certd.insert(cert_stub, |_cert_stub, disk_bytes| {
            let disk: Option<Cow<LazyCert>>
                = if let Some(disk_bytes) = disk_bytes.as_ref()
            {
                let mut parser = RawCertParser::from_bytes(disk_bytes)
                    .with_context(|| {
                        format!("Parsing {} as returned from the cert directory",
                                fpr)
                    })
                    .map_err(|err| {
                        t!("Reading disk version: {}", err);
                        err
                    })?;
                let disk = parser.next().transpose()
                    .with_context(|| {
                        format!("Parsing {} as returned from the cert directory",
                                fpr)
                    })
                    .map_err(|err| {
                        t!("Parsing disk version: {}", err);
                        err
                    })?;
                if let Some(disk) = disk {
                    Some(Cow::Owned(LazyCert::from(disk)))
                } else {
                    None
                }
            } else {
                t!("No disk version");
                None
            };

            let merged_ = merge_strategy.merge(cert, disk)
                .with_context(|| {
                    format!("Merging versions of {}", fpr)
                })
                .map_err(|err| {
                    t!("Merging: {}", err);
                    err
                })?;
            let bytes = merged_.to_vec()?.into_boxed_slice();
            merged = Some(merged_);
            Ok(bytes)
        })?;

        let merged = merged.expect("set");
        // Inserting into the in-memory index is infallible.
        if let Err(err) = self.certs.update(merged) {
            t!("Inserting {} into in-memory index: {}", fpr, err);
        }
        // Annoyingly, there is no easy way to get index to return a
        // reference to what it just inserted.
        Ok(self.certs.lookup_by_cert_fpr(&fpr).expect("just set"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context;

    use openpgp::packet::UserID;
    use openpgp::serialize::Serialize;

    use crate::store::StoreError;
    use crate::print_error_chain;

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
        let mut certs_read = certd.certs().collect::<Vec<_>>();
        assert_eq!(
            certs_read.len(), certs.len(),
            "Looks like you're exhausting the available file descriptors");

        certs_read.sort_by_key(|c| c.fingerprint());
        let certs_read_fpr
            = certs_read.iter().map(|c| c.fingerprint()).collect::<Vec<_>>();
        assert_eq!(certs_fpr, certs_read_fpr);

        // Test Store::by_cert.
        for cert in certs.iter() {
            let certs_read = certd.lookup_by_cert(&cert.key_handle()).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");
            assert_eq!(&cert_read, cert);
        }

        for subkey in subkeys_fpr.iter() {
            let kh = KeyHandle::from(subkey.clone());
            match certd.lookup_by_cert(&kh) {
                Ok(certs) => panic!("Expected nothing, got {} certs", certs.len()),
                Err(err) => {
                    if let Some(&StoreError::NotFound(ref got))
                        = err.downcast_ref::<StoreError>()
                    {
                        assert_eq!(&kh, got);
                    } else {
                        panic!("Expected NotFound, got: {}", err);
                    }
                }
            }
        }

        // Test Store::lookup_by_key.
        for fpr in certs.iter().map(|cert| cert.fingerprint())
            .chain(subkeys_fpr.iter().cloned())
        {
            let certs_read
                = certd.lookup_by_key(&KeyHandle::from(fpr.clone())).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");

            assert!(cert_read.keys().any(|k| k.fingerprint() == fpr));
        }

        // Test Store::lookup_by_userid.
        for userid in userids.iter() {
            let userid = UserID::from(&userid[..]);

            let certs_read
                = certd.lookup_by_userid(&userid).expect("present");
            // We expect exactly one cert.
            assert_eq!(certs_read.len(), 1);
            let cert_read = certs_read.into_iter().next().expect("have one")
                .as_cert().expect("valid");

            assert!(cert_read.userids().any(|u| u.userid() == &userid));
        }

        Ok(())
    }
}
