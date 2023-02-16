use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::cert::raw::RawCert;
use openpgp::cert::raw::RawCertParser;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::KeyHandle;
use openpgp::parse::Parse;
use openpgp::Result;

use crate::LazyCert;
use crate::store::Store;
use crate::store::StoreError;
use crate::store::StoreUpdate;
use crate::store::UserIDIndex;
use crate::store::UserIDQueryParams;

const TRACE: bool = false;

/// Manages a slice of bytes, `RawCert`s, `Cert`s, or `LazyCert`s.
///
/// `Cert`s implements `StoreUpdate`, but it does not write the
/// updates to disk; they are only updated in memory.
pub struct Certs<'a> {
    // Indexed by primary key fingerprint.
    certs: HashMap<Fingerprint, LazyCert<'a>>,
    // Indexed by a key's KeyID (primary key or subkey) and maps to
    // the primary key.
    keys: HashMap<KeyID, Vec<Fingerprint>>,

    userid_index: UserIDIndex,
}

impl<'a> Certs<'a>
{
    /// Returns an empty `Certs` store.
    ///
    /// This is useful as a placeholder.  But, certificates can also
    /// be added to it using the [`StoreUpdate`] interface.
    pub fn empty() -> Self {
        Certs {
            certs: HashMap::new(),
            keys: HashMap::new(),
            userid_index: UserIDIndex::new(),
        }
    }

    /// Returns a new `Certs`.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        tracer!(TRACE, "Certs::from_bytes");

        let raw_certs = RawCertParser::from_bytes(bytes)?
            .filter_map(|c| {
                match c {
                    Ok(c) => Some(c),
                    Err(err) => {
                        t!("Parsing raw certificate: {}", err);
                        None
                    }
                }
            });
        Self::from_raw_certs(raw_certs)
    }

    /// Returns a new `Certs`.
    pub fn from_certs(certs: impl Iterator<Item=Cert>)
        -> Result<Self>
    {
        Self::from_lazy_certs(certs.map(LazyCert::from_cert))
    }

    /// Returns a new `Certs`.
    pub fn from_raw_certs(raw_certs: impl Iterator<Item=RawCert<'a>>)
        -> Result<Self>
    {
        Self::from_lazy_certs(raw_certs.map(LazyCert::from_raw_cert))
    }

    /// Returns a new `Certs`.
    pub fn from_lazy_certs(certs: impl Iterator<Item=LazyCert<'a>>)
        -> Result<Self>
    {
        tracer!(TRACE, "Certs::from_raw_certs");

        let mut r = Self::empty();
        for cert in certs {
            r.insert_lazy_cert(cert).expect("implementation doesn't fail")
        }

        Ok(r)
    }
}

impl<'a> Store<'a> for Certs<'a>
{
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Certs::by_cert");

        match kh {
            KeyHandle::Fingerprint(fpr) => {
                self.by_cert_fpr(fpr).map(|c| vec![ c ])
            }
            KeyHandle::KeyID(keyid) => {
                let certs: Vec<Cow<LazyCert>> = self.keys.get(&keyid)
                    .ok_or_else(|| {
                        anyhow::Error::from(
                            StoreError::NotFound(kh.clone()))
                    })?
                    .iter()
                    .filter_map(|fpr| self.certs.get(fpr))
                    // Check the constaints before we convert the
                    // rawcert to a cert.
                    .filter(|cert| cert.key_handle().aliases(kh))
                    .map(|cert| Cow::Borrowed(cert))
                    .collect();

                if certs.is_empty() {
                    Err(StoreError::NotFound(kh.clone()).into())
                } else {
                    Ok(certs)
                }
            }
        }
    }

    fn by_cert_fpr(&self, fingerprint: &Fingerprint) -> Result<Cow<LazyCert<'a>>> {
        tracer!(TRACE, "Certs::by_cert_fpr");

        if let Some(cert) = self.certs.get(fingerprint) {
            Ok(Cow::Borrowed(cert))
        } else {
            Err(StoreError::NotFound(
                KeyHandle::from(fingerprint.clone())).into())
        }
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Certs::by_key");

        let keyid = KeyID::from(kh);
        let certs: Vec<Cow<LazyCert<'a>>> = self.keys.get(&keyid)
            .ok_or_else(|| {
                anyhow::Error::from(
                    StoreError::NotFound(kh.clone()))
            })?
            .iter()
            .filter_map(|fpr| self.certs.get(fpr))
            // Check the constaints before we convert the rawcert to a
            // cert.
            .filter(|cert| {
                cert.keys().any(|k| k.key_handle().aliases(kh))
            })
            .map(|cert| Cow::Borrowed(cert))
            .collect();

        if certs.is_empty() {
            Err(StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(certs)
        }
    }

    fn select_userid(&self, params: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        tracer!(TRACE, "RawCert::select_userid");
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

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        Box::new(self.certs.keys().cloned())
    }

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b> where 'a: 'b
    {
        Box::new(self.certs
            .values()
            .map(|cert| Cow::Borrowed(cert)))
    }

    fn precompute(&self) {
        // XXX: LazyCert is current not Sync and not Send (due to the
        // use of RefCell).  That means the following doesn't work.
        // We need to decide if we want to use Arc instead of Rc, etc.

//        tracer!(TRACE, "Certs::precompute");
//
//        use crossbeam::thread;
//        use crossbeam::channel::unbounded as channel;
//
//        // Avoid an extra level of indentation.
//        let result = thread::scope(|thread_scope| {
//        let mut certs: Vec<&LazyCert>
//            = self.certs.values().filter(|c| {
//                c.raw_cert().is_some()
//            }).collect();
//        let cert_count = certs.len();
//
//        // The threads.  We start them on demand.
//        let threads = if cert_count < 16 {
//            // The keyring is small, limit the number of threads.
//            2
//        } else {
//            // Sort the certificates so they are ordered from most
//            // packets to least.  More packets implies more work, and
//            // this will hopefully result in a more equal distribution
//            // of load.
//            certs.sort_unstable_by_key(|c| {
//                usize::MAX - c.raw_cert().map(|r| r.count()).unwrap_or(0)
//            });
//
//            // Use at least one and not more than we have cores.
//            num_cpus::get().max(1)
//        };
//
//        // A communication channel for sending work to the workers.
//        let (work_tx, work_rx) = channel();
//
//        let mut threads_extant = Vec::new();
//
//        for cert in certs.into_iter() {
//            if threads_extant.len() < threads {
//                let tid = threads_extant.len();
//                t!("Starting thread {} of {}",
//                   tid, threads);
//
//                let mut work = Some(Ok(cert));
//
//                // The thread's state.
//                let work_rx = work_rx.clone();
//
//                threads_extant.push(thread_scope.spawn(move |_| {
//                    loop {
//                        match work.take().unwrap_or_else(|| work_rx.recv()) {
//                            Err(_) => break,
//                            Ok(raw) => {
//                                let fpr = cert.fingerprint();
//                                t!("Thread {} dequeuing {}!", tid, fpr);
//                                // Silently ignore errors.  This will
//                                // be caught later when the caller
//                                // looks this one up.
//
//                                let _ = raw.to_cert();
//                            }
//                        }
//                    }
//
//                    t!("Thread {} exiting", tid);
//                }));
//            } else {
//                work_tx.send(cert).unwrap();
//            }
//        }
//
//        // When the threads see this drop, they will exit.
//        drop(work_tx);
//        }); // thread scope.
//
//        // We're just caching results so we can ignore errors.
//        if let Err(err) = result {
//            t!("{:?}", err);
//        }
    }
}

impl<'a> StoreUpdate<'a> for Certs<'a> {
    fn insert_lazy_cert(&mut self, cert: LazyCert<'a>) -> Result<()> {
        let fpr = cert.fingerprint();

        // Populate the key map.
        for k in cert.keys() {
            match self.keys.entry(k.keyid()) {
                Entry::Occupied(mut oe) => {
                    let fprs = oe.get_mut();
                    if ! fprs.contains(&fpr) {
                        fprs.push(fpr.clone());
                    }
                }
                Entry::Vacant(ve) => {
                    ve.insert(vec![ fpr.clone() ]);
                }
            }
        }

        self.userid_index.insert(&fpr, cert.userids());

        // Add the cert fingerprint -> cert entry.
        match self.certs.entry(fpr.clone()) {
            Entry::Occupied(mut oe) => {
                let entry = oe.get_mut();
                if let Ok(a) = entry.to_cert() {
                    if let Ok(b) = cert.to_cert() {
                        let merged = a.clone().merge_public(b.clone())
                            .expect("same cert");
                        *entry = LazyCert::from_cert(merged);
                    }
                }
            }
            Entry::Vacant(ve) => {
                ve.insert(cert);
            }
        }

        Ok(())
    }
}
