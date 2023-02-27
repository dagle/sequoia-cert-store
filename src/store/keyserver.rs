use std::borrow::Borrow;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::policy::NullPolicy;

use sequoia_net as net;

use crate::email_to_userid;
use crate::LazyCert;
use crate::Store;
use crate::store::StoreError;
use crate::store::UserIDQueryParams;

use super::TRACE;

const NP: &NullPolicy = &NullPolicy::new();

// Reliable keyservers.
/// keys.openpgp.org.
pub const KEYS_OPENPGP_ORG_URL: &str = "hkps://keys.openpgp.org";
/// A reliable SKS keyserver.
pub const SKS_URL: &str = "hkps://keyserver.ubuntu.com";
/// mailvelope's keyserver.
pub const MAILVELOPE_URL: &str = "hkps://keys.mailvelope.com";
/// proton's keyserver.
pub const PROTON_URL: &str = "hkps://api.protonmail.ch";

/// A keyserver backend.
pub struct KeyServer<'a> {
    keyserver: RefCell<net::KeyServer>,

    // A cache.  We only cache certificates; we don't cache User ID
    // searches.

    // Primary keys and subkeys.
    // XXX: Use an Rc<LazyCert> instead.
    hits_fpr: RefCell<HashMap<Fingerprint, Rc<LazyCert<'a>>>>,
    hits_keyid: RefCell<HashMap<KeyID, Fingerprint>>,
    // What we failed to look up.
    misses_fpr: RefCell<HashSet<Fingerprint>>,
    misses_keyid: RefCell<HashSet<KeyID>>,
}

impl KeyServer<'_> {
    /// Returns a new key server instance.
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            keyserver: RefCell::new(
                net::KeyServer::new(net::Policy::Encrypted, url)?),
            hits_fpr: Default::default(),
            hits_keyid: Default::default(),
            misses_fpr: Default::default(),
            misses_keyid: Default::default(),
        })
    }

    /// Returns a key server instance that uses `keys.openpgp.org`.
    pub fn keys_openpgp_org() -> Result<Self> {
        Self::new(KEYS_OPENPGP_ORG_URL)
    }

    /// Returns a key server instance that uses a reliable SKS
    /// keyserver.
    pub fn sks() -> Result<Self> {
        Self::new(SKS_URL)
    }

    /// Returns a key server instance that uses mailvelope's
    /// keyserver.
    pub fn mailvelope() -> Result<Self> {
        Self::new(MAILVELOPE_URL)
    }

    /// Returns a key server instance that uses proton's keyserver.
    pub fn proton() -> Result<Self> {
        Self::new(PROTON_URL)
    }
}

impl<'a> KeyServer<'a> {
    // Looks for a certificate in the cache.
    fn check_cache(&self, kh: &KeyHandle)
        -> Option<Result<Vec<Cow<LazyCert<'a>>>>>
    {
        let kh_;
        let kh = if let KeyHandle::KeyID(keyid) = kh {
            if let Some(fpr) = self.hits_keyid.borrow().get(keyid) {
                kh_ = KeyHandle::Fingerprint(fpr.clone());
                &kh_
            } else if self.misses_keyid.borrow().get(keyid).is_some() {
                return Some(Err(StoreError::NotFound(
                    KeyHandle::from(kh.clone())).into()));
            } else {
                kh
            }
        } else {
            kh
        };
        if let KeyHandle::Fingerprint(fpr) = kh {
            if let Some(cert) = self.hits_fpr.borrow().get(fpr) {
                return Some(Ok(vec![ Cow::Owned(cert.as_ref().clone()) ]));
            }
            if self.misses_fpr.borrow().get(fpr).is_some() {
                return Some(Err(StoreError::NotFound(
                    KeyHandle::from(kh.clone())).into()));
            }
        }

        None
    }

    // Adds the cert to the in-memory cache.
    fn cache(&self, cert: Cert) {
        let cert = Rc::new(LazyCert::from(cert));

        let mut hits_fpr = self.hits_fpr.borrow_mut();
        let mut hits_keyid = self.hits_keyid.borrow_mut();

        for k in cert.keys() {
            hits_fpr.insert(k.fingerprint(), Rc::clone(&cert));
            hits_keyid.insert(k.keyid(), k.fingerprint());
        }
    }
}

impl<'a> Store<'a> for KeyServer<'a> {
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let mut certs = self.by_key(kh)?;

        // The match may be on a subkey.  Only return the certificates
        // whose primary key aliases kh.
        certs.retain(|cert| {
            kh.aliases(KeyHandle::from(cert.fingerprint()))
        });

        if certs.is_empty() {
            Err(StoreError::NotFound(KeyHandle::from(kh.clone())).into())
        } else {
            Ok(certs)
        }
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "KeyServer::by_key");

        // Check the cache.
        if let Some(r) = self.check_cache(kh) {
            return r;
        }

        // It's not in the cache, look it up on the key server.
        let rt = tokio::runtime::Runtime::new().unwrap();

        // The keyserver interface currently only returns a single
        // result.
        let r = rt.block_on(async {
            self.keyserver.borrow_mut().get(kh.clone()).await
        });

        match r {
            Ok(cert) => {
                // Add the result to the cache.
                self.cache(cert.clone());

                // Make sure the key server gave us the right
                // certificate.
                if cert.keys().any(|k| k.key_handle().aliases(kh)) {
                    Ok(vec![ Cow::Owned(LazyCert::from(cert)) ])
                } else {
                    t!("keyserver returned the wrong key: {} (wanted: {})",
                       cert.key_handle(), kh);
                    Err(StoreError::NotFound(
                        KeyHandle::from(kh.clone())).into())
                }
            }
            Err(err) => {
                if let Some(net::Error::NotFound)
                    = err.downcast_ref::<net::Error>()
                {
                    Err(StoreError::NotFound(
                        KeyHandle::from(kh.clone())).into())
                } else {
                    Err(err)
                }
            }
        }
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        tracer!(TRACE, "KeyServer::select_userid");

        t!("{}", pattern);
        t!("Looking {:?} up on the keyserver... ", pattern);

        let email = if query.email && query.anchor_start && query.anchor_end {
            match email_to_userid(pattern) {
                Ok(email) => {
                    if let Ok(email) = std::str::from_utf8(email.value()) {
                        Some(email.to_string())
                    } else {
                        None
                    }
                },
                Err(err) => {
                    t!("{:?}: invalid email address: {}", pattern, err);
                    None
                }
            }
        } else {
            None
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (ks, wkd) = rt.block_on(async {
            // Query the keyserver.
            let mut ks = self.keyserver.borrow_mut();
            let ks = ks.search(pattern);

            // And the WKD (if it appears to be an email address).
            let wkd = async {
                if let Some(email) = email.as_ref() {
                    net::wkd::get(email).await
                } else {
                    // If it is not an email, it's not an error.
                    Ok(Vec::new())
                }
            };

            tokio::join!(ks, wkd)
        });

        let mut certs = Vec::new();
        match ks {
            Ok(c) => {
                t!("Key server returned {} results", c.len());
                certs.extend(c);
            },
            Err(err) => t!("Key server response: {}", err),
        }
        match wkd {
            Ok(c) => {
                t!("WKD server returned {} results", c.len());
                certs.extend(c);
            },
            Err(err) => t!("WKD server response: {}", err),
        }

        // Sort, merge, and cache.
        certs.sort_by_key(|c| c.fingerprint());
        certs.dedup_by(|a, b| {
            if a.fingerprint() != b.fingerprint() {
                return false;
            }

            // b is kept.  So merge into b.
            match b.clone().merge_public(a.clone()) {
                Ok(combined) => *b = combined,
                Err(err) => {
                    t!("Merging copies of {}: {}",
                       a.keyid(), err);
                }
            }

            true
        });

        // Add the results to the cache.
        certs.iter().cloned().for_each(|cert| self.cache(cert));

        // Only keep the certificates that actually satisfy the
        // constraints.
        certs.retain(|cert| {
            query.check_cert(cert.borrow(), pattern)
        });

        t!("Got {} results:\n  {}",
           certs.len(),
           certs.iter().map(|cert: &Cert| {
               format!(
                   "{} ({})",
                   cert.keyid().to_hex(),
                   cert.with_policy(NP, None)
                       .and_then(|vc| vc.primary_userid())
                       .map(|ua| {
                           String::from_utf8_lossy(ua.userid().value()).into_owned()
                       })
                       .unwrap_or_else(|_| {
                           cert.userids().next()
                               .map(|userid| {
                                   String::from_utf8_lossy(userid.value()).into_owned()
                               })
                               .unwrap_or("<unknown>".into())
                       }))
           })
           .collect::<Vec<_>>()
           .join("\n  "));

        if certs.is_empty() {
            Err(StoreError::NoMatches(pattern.to_string()).into())
        } else {
            Ok(certs.into_iter().map(|cert| {
                Cow::Owned(LazyCert::from(cert))
            }).collect())
        }
    }

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        // Return nothing, not even the entries in our cache.
        Box::new(std::iter::empty())
    }
}
