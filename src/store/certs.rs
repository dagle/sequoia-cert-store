use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use smallvec::SmallVec;
use smallvec::smallvec;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::cert::raw::RawCert;
use openpgp::cert::raw::RawCertParser;
use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::KeyHandle;
use openpgp::parse::Parse;
use openpgp::Result;

use crate::LazyCert;
use crate::store::MergeCerts;
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
    keys: HashMap<KeyID, SmallVec<[Fingerprint; 1]>>,

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
        Self::from_certs(raw_certs)
    }

    /// Returns a new `Certs`.
    pub fn from_certs<I>(certs: impl IntoIterator<Item=I>)
        -> Result<Self>
        where I: Into<LazyCert<'a>>
    {
        let mut r = Self::empty();
        for cert in certs {
            r.update(Cow::Owned(cert.into())).expect("implementation doesn't fail")
        }

        Ok(r)
    }
}

impl<'a> Store<'a> for Certs<'a>
{
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Certs::lookup_by_cert");

        match kh {
            KeyHandle::Fingerprint(fpr) => {
                self.lookup_by_cert_fpr(fpr).map(|c| vec![ c ])
            }
            KeyHandle::KeyID(keyid) => {
                let certs: Vec<Cow<LazyCert>> = self.keys.get(&keyid)
                    .ok_or_else(|| {
                        anyhow::Error::from(
                            StoreError::NotFound(kh.clone()))
                    })?
                    .iter()
                    .filter_map(|fpr| self.certs.get(fpr))
                    // Check the constraints before we convert the
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

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint) -> Result<Cow<LazyCert<'a>>> {
        tracer!(TRACE, "Certs::lookup_by_cert_fpr");

        if let Some(cert) = self.certs.get(fingerprint) {
            Ok(Cow::Borrowed(cert))
        } else {
            Err(StoreError::NotFound(
                KeyHandle::from(fingerprint.clone())).into())
        }
    }

    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Certs::lookup_by_key");

        let keyid = KeyID::from(kh);
        let certs: Vec<Cow<LazyCert<'a>>> = self.keys.get(&keyid)
            .ok_or_else(|| {
                anyhow::Error::from(
                    StoreError::NotFound(kh.clone()))
            })?
            .iter()
            .filter_map(|fpr| self.certs.get(fpr))
            // Check the constraints before we convert the rawcert to a
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
                self.lookup_by_cert_fpr(&fpr).expect("indexed")
            })
            .collect();

        Ok(matches)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        Box::new(self.certs.keys().cloned())
    }

    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        Box::new(self.certs
            .values()
            .map(|cert| Cow::Borrowed(cert)))
    }

    fn prefetch_all(&mut self) {
        self.prefetch_some(Vec::new())
    }

    fn prefetch_some(&mut self, khs: Vec<KeyHandle>) {
        // LazyCert is currently not Sync or Send (due to the use of
        // RefCell).  This requires a bit of acrobatics to get right.

        tracer!(TRACE, "Certs::prefetch_some");
        t!("Prefetch: {} certificates", khs.len());

        use crossbeam::thread;
        use crossbeam::channel::unbounded as channel;

        // Avoid an extra level of indentation.
        let result = thread::scope(|thread_scope| {
        let mut certs: Vec<RawCert>
            = self.certs.iter().filter_map(|(fpr, cert)| {
                if cert.raw_cert().is_some() {
                    if khs.is_empty()
                        || khs.iter()
                               .any(|kh| {
                                   kh.aliases(&KeyHandle::from(fpr.clone()))
                               })
                    {
                        // Unfortunately we have to clone the bytes,
                        // because LazyCert puts the RawCert in a
                        // RefCell.
                        t!("Queuing {} to be prefetched", fpr);
                        cert.clone().into_raw_cert().ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }).collect();
        let cert_count = certs.len();

        // The threads.  We start them on demand.
        let threads = if cert_count < 16 {
            // The keyring is small, limit the number of threads.
            2
        } else {
            // Sort the certificates so they are ordered from most
            // packets to least.  More packets implies more work, and
            // this will hopefully result in a more equal distribution
            // of load.
            certs.sort_unstable_by_key(|c| {
                usize::MAX - c.count()
            });

            // Use at least one and not more than we have cores.
            num_cpus::get().max(1)
        };
        t!("Using {} threads", threads);

        // A communication channel for sending work to the workers.
        let (work_tx, work_rx) = channel();
        // A communication channel for returning returns to the main
        // thread.
        let (results_tx, results_rx) = channel();

        let mut threads_extant = Vec::new();

        for cert in certs.into_iter() {
            if threads_extant.len() < threads {
                let tid = threads_extant.len();
                t!("Starting thread {} of {}",
                   tid, threads);

                let mut work = Some(Ok(cert));

                // The thread's state.
                let work_rx = work_rx.clone();
                let results_tx = results_tx.clone();

                threads_extant.push(thread_scope.spawn(move |_| {
                    loop {
                        match work.take().unwrap_or_else(|| work_rx.recv()) {
                            Err(_) => break,
                            Ok(raw) => {
                                t!("Thread {} dequeuing {}!",
                                   tid, raw.keyid());

                                // Silently ignore errors.  This will
                                // be caught later when the caller
                                // looks this one up.
                                match Cert::try_from(&raw) {
                                    Ok(cert) => {
                                        let _ = results_tx.send(cert);
                                    }
                                    Err(err) => {
                                        t!("Parsing raw cert {}: {}",
                                           raw.keyid(), err);
                                    }
                                }
                            }
                        }
                    }

                    t!("Thread {} exiting", tid);
                }));
            } else {
                work_tx.send(cert).unwrap();
            }
        }

        // When the threads see this drop, they will exit.
        drop(work_tx);
        // Drop our reference to results_tx.  When the last thread
        // exits, the last reference will be dropped and the loop
        // below will exit.
        drop(results_tx);

        let mut count = 0;
        while let Ok(cert) = results_rx.recv() {
            let fpr = cert.fingerprint();
            t!("Caching {}", fpr);
            self.certs.insert(fpr, cert.into());
            count += 1;
        }
        t!("Prefetched {} certificates, ({} RawCerts had errors)",
           count, cert_count - count);
        }); // thread scope.

        // We're just caching results so we can ignore errors.
        if let Err(err) = result {
            t!("{:?}", err);
        }
    }
}

impl<'a> StoreUpdate<'a> for Certs<'a> {
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        tracer!(TRACE, "Certs::update_by");

        let fpr = cert.fingerprint();

        // Add the cert fingerprint -> cert entry.
        let merged: Cow<LazyCert>;
        match self.certs.entry(fpr.clone()) {
            Entry::Occupied(mut oe) => {
                t!("Updating {}", fpr);

                let old = Cow::Borrowed(oe.get());

                merged = merge_strategy.merge(cert, Some(old))
                    .with_context(|| {
                        format!("Merging two version of {}", fpr)
                    })?;

                *oe.get_mut() = merged.to_owned().into_owned();
            }
            Entry::Vacant(ve) => {
                t!("Inserting {}", fpr);

                merged = merge_strategy.merge(cert, None)?;
                ve.insert(merged.to_owned().into_owned());
            }
        }

        // Populate the key map.  This is a merge so we are not
        // removing anything.
        for k in merged.keys() {
            match self.keys.entry(k.keyid()) {
                Entry::Occupied(mut oe) => {
                    let fprs = oe.get_mut();
                    if ! fprs.contains(&fpr) {
                        fprs.push(fpr.clone());
                    }
                }
                Entry::Vacant(ve) => {
                    ve.insert(smallvec![ fpr.clone() ]);
                }
            }
        }

        self.userid_index.insert(&fpr, merged.userids());

        Ok(merged)
    }
}
