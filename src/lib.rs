//! A certificate store abstraction.
//!
//! This crates provides a unified interface for different certificate
//! stores via the [`Store`] and [`StoreUpdate`] traits.  It also
//! provides a number of helper functions and data structures, like
//! [`UserIDIndex`] to help implement this functionality.
//!
//! [`UserIDIndex`]: store::UserIDIndex
//!
//! The [`CertStore`] data structure combines multiple certificate
//! backends in a transparent way to users.
//!
//! # Examples
//!
//! ```rust
//! use std::borrow::Cow;
//!
//! use sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! use openpgp::cert::Cert;
//! use openpgp::cert::CertBuilder;
//!
//! use sequoia_cert_store as cert_store;
//! use cert_store::CertStore;
//! use cert_store::LazyCert;
//! use cert_store::Store;
//! use cert_store::StoreUpdate;
//!
//! # fn main() -> Result<()> {
//! // Create an in-memory certificate store.  To use the default
//! // on-disk certificate store, use `CertStore::new`.
//! let mut certs = CertStore::empty();
//!
//! let (cert, _rev) = CertBuilder::new().generate()?;
//! let fpr = cert.fingerprint();
//!
//! // It's not in the cert store yet:
//! assert!(certs.lookup_by_cert_fpr(&fpr).is_err());
//!
//! // Insert a certificate.  If using a backing store, it would
//! // also be written to disk.
//! certs.update(Cow::Owned(LazyCert::from(cert)))?;
//!
//! // Make sure it is there.
//! let cert = certs.lookup_by_cert_fpr(&fpr).expect("present");
//! assert_eq!(cert.fingerprint(), fpr);
//!
//! // Resolve the `LazyCert` to a `Cert`.  Certificates are stored
//! // using `LazyCert` so that it is possible to work with `RawCert`s
//! // and `Cert`s.  This allows the implementation to defer fully parsing
//! // and validating the certificate until it is actually needed.
//! let cert: &Cert = cert.to_cert()?;
//! # Ok(()) }
//! ```
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::packet::UserID;

#[macro_use] mod log;
#[macro_use] mod macros;

pub mod store;
pub use store::Store;
pub use store::StoreUpdate;
mod cert_store;
pub use cert_store::CertStore;
pub use cert_store::AccessMode;

mod lazy_cert;
pub use lazy_cert::LazyCert;

const TRACE: bool = false;

/// Prints the error and causes, if any.
#[allow(unused)]
fn print_error_chain(err: &anyhow::Error) {
    let _ = write_error_chain_into(&mut std::io::stderr(), err);
}

/// Prints the error and causes, if any.
fn write_error_chain_into(sink: &mut dyn std::io::Write, err: &anyhow::Error)
                          -> Result<()> {
    writeln!(sink, "           {}", err)?;
    for cause in err.chain().skip(1) {
        writeln!(sink, "  because: {}", cause)?;
    }
    Ok(())
}

/// Converts an email address to a User ID.
///
/// If the email address is not valid, returns an error.
///
/// The email address must be a bare email address.  That is it must
/// have the form `localpart@example.org`, and not be surrounded by
/// angle brackets like `<localpart@example.org>`.
///
/// The email address is checked for validity.  Specifically, it is
/// checked to conform with [`RFC 2822`]'s [`addr-spec`] grammar.
///
/// Returns a UserID containing the normalized User ID in angle
/// brackets.
///
/// [`RFC 2822`]: https://www.rfc-editor.org/rfc/rfc2822
/// [`addr-spec`]: https://www.rfc-editor.org/rfc/rfc2822#section-3.4.1
pub fn email_to_userid(email: &str) -> Result<UserID> {
    let email_check = UserID::from(format!("<{}>", email));
    match email_check.email() {
        Ok(Some(email_check)) => {
            if email != email_check {
                return Err(anyhow::anyhow!(
                    "{:?} does not appear to be an email address",
                    email));
            }
        }
        Ok(None) => {
            return Err(anyhow::anyhow!(
                "{:?} does not appear to be an email address",
                email));
        }
        Err(err) => {
            return Err(err.context(format!(
                "{:?} does not appear to be an email address",
                email)));
        }
    }

    let userid = UserID::from(&email[..]);
    match userid.email_normalized() {
        Err(err) => {
            Err(err.context(format!(
                "'{}' is not a valid email address", email)))
        }
        Ok(None) => {
            Err(anyhow::anyhow!("'{}' is not a valid email address", email))
        }
        Ok(Some(_email)) => {
            Ok(userid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::borrow::Cow;
    use std::path::PathBuf;
    use std::str;

    use anyhow::Context;

    use openpgp::Fingerprint;
    use openpgp::KeyHandle;
    use openpgp::KeyID;
    use openpgp::Cert;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::Serialize;

    use openpgp_cert_d as cert_d;

    use store::Certs;
    use store::StoreError;
    use store::UserIDQueryParams;

    fn certd_merge(new: cert_d::Data, disk: Option<cert_d::Data>)
        -> cert_d::Result<cert_d::Data> {
        if let Some(disk) = disk {
            let new = Cert::from_bytes(&new).expect("valid");
            let disk = Cert::from_bytes(&disk).expect("valid");
            let merged = new.merge_public(disk).expect("valid");
            let mut bytes = Vec::new();
            merged.serialize(&mut bytes).expect("valid");
            Ok(bytes.into_boxed_slice())
        } else {
            Ok(new)
        }
    }

    include!("../tests/keyring.rs");

    fn test_backend<'a, B>(backend: B)
        where B: Store<'a>
    {
        // Check Store::list.
        {
            let mut got: Vec<Fingerprint> = backend.fingerprints().collect();
            got.sort();
            let mut expected: Vec<Fingerprint> = keyring::certs.iter()
                .map(|c| c.fingerprint.parse::<Fingerprint>().expect("valid"))
                .collect();
            expected.sort();
            expected.dedup();
            assert_eq!(got.len(), expected.len());
            assert_eq!(got, expected);
        }

        // Check Store::iter.
        {
            let mut got: Vec<Fingerprint>
                = backend.certs().map(|c| c.fingerprint()).collect();
            got.sort();
            let mut expected: Vec<Fingerprint> = keyring::certs.iter()
                .map(|c| c.fingerprint.parse::<Fingerprint>().expect("valid"))
                .collect();
            expected.sort();
            expected.dedup();
            assert_eq!(got.len(), expected.len());
            assert_eq!(got, expected);
        }

        // Iterate over the certificates in the keyring and check that
        // can look up the certificate by fingerprint, by key, by User
        // ID, and by email in various ways.
        for handle in keyring::certs.iter() {
            let fpr: Fingerprint = handle.fingerprint.parse().expect("valid");
            let cert = handle.to_cert().expect("valid");
            assert_eq!(fpr, cert.fingerprint(),
                       "{}", handle.base);
            let keyid = KeyID::from(fpr.clone());

            // Check by_cert_fpr.
            let got = backend.lookup_by_cert_fpr(&fpr).expect("present");
            assert_eq!(got.fingerprint(), fpr,
                       "{}, by_cert_fpr, primary", handle.base);

            // Look up by subkey and make sure we don't get cert.
            // Note: if a subkey is also a primary key (as is the case
            // for the ed certificate), then we'll get a certificate
            // back.
            for sk in cert.keys().subkeys() {
                match backend.lookup_by_cert_fpr(&sk.fingerprint()) {
                    Ok(got) => {
                        // The subkey could be a primary key for a
                        // different certificate.  So, make sure it is
                        // not
                        assert!(
                            keyring::certs.iter().any(|c| {
                                c.fingerprint.parse::<Fingerprint>().unwrap()
                                    == got.fingerprint()
                            }),
                            "{}, lookup_by_cert_fpr, subkey, unexpectedly got {}",
                            handle.base, got.fingerprint());
                    }
                    Err(err) => {
                        match err.downcast_ref::<StoreError>() {
                            Some(StoreError::NotFound(_)) => (),
                            _ => panic!("Expected StoreError::NotFound, \
                                         got: {}",
                                        err),
                        }
                    },
                }
            }

            // Check lookup_by_cert using key ids.
            let got = backend.lookup_by_cert(&KeyHandle::from(&keyid))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, lookup_by_cert, keyid, primary", handle.base);

            // Look up by subkey.  This will only return something if
            // the subkey also happens to be a primary key.
            for sk in cert.keys().subkeys() {
                match backend.lookup_by_cert(&KeyHandle::from(sk.keyid())) {
                    Ok(got) => {
                        // Make sure subkey is also a primary key.
                        for got in got.into_iter() {
                            assert!(
                                keyring::certs.iter().any(|c| {
                                    c.fingerprint.parse::<Fingerprint>()
                                        .unwrap()
                                        == got.fingerprint()
                                }),
                                "{}, lookup_by_cert_fpr, subkey, \
                                 unexpectedly got {}",
                                handle.base, got.fingerprint());
                        }
                    }
                    Err(err) => {
                        match err.downcast_ref::<StoreError>() {
                            Some(StoreError::NotFound(_)) => (),
                            _ => panic!("Unexpected failure: {}", err),
                        }
                    },
                }
            }

            // Check lookup_by_key using fingerprints.
            let got = backend.lookup_by_key(&KeyHandle::from(fpr.clone()))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, lookup_by_key, with fingerprint, primary",
                    handle.base);

            // Look up by subkey and make sure we get cert.
            for sk in cert.keys().subkeys() {
                let got = backend.lookup_by_key(
                    &KeyHandle::from(sk.fingerprint()))
                    .expect("present");
                assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                        "{}, lookup_by_key({}), with fingerprint, subkey",
                        handle.base, sk.fingerprint());
            }


            // Check lookup_by_key using keyids.
            let got = backend.lookup_by_key(&KeyHandle::from(keyid.clone()))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, lookup_by_key, with keyid, primary", handle.base);

            // Look up by subkey and make sure we get cert.
            for sk in cert.keys().subkeys() {
                let got = backend.lookup_by_key(&KeyHandle::from(sk.keyid()))
                    .expect("present");
                assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                        "{}, lookup_by_key, with keyid, subkey", handle.base);
            }


            // Check look up by User ID address by querying for each
            // User ID, email, domain, etc.
            for ua in cert.userids() {
                let userid = ua.userid();

                // Search by exact user id.
                let got = backend.lookup_by_userid(userid)
                    .expect(&format!("{}, lookup_by_userid({:?})",
                                     handle.base, userid));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, lookup_by_userid({:?})", handle.base, userid);

                // Extract an interior substring (nor anchored at the
                // start or the end), and uppercase it.
                let pattern = str::from_utf8(userid.value()).expect("utf-8");
                let pattern = &pattern[1..pattern.len() - 1];
                let pattern = pattern.to_uppercase();

                // grep removes all constraints so we should still
                // find it.
                let got = backend.grep_userid(&pattern)
                    .expect(&format!("{}, grep_userid({:?})",
                                     handle.base, pattern));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, grep_userid({:?})", handle.base, pattern);

                // Now use an anchor at the start, or the end, ignore
                // case, or not.  The only one combination that should
                // return any results is no constraints, which we
                // tested above.
                for (start, end, ignore_case) in
                    [(false, false, false),
                     //(false, false,  true),
                     (false,  true, false),
                     (false,  true,  true),
                     ( true, false, false),
                     ( true, false,  true),
                     ( true,  true, false),
                     ( true,  true,  true)]
                {
                    let result = backend.select_userid(
                        UserIDQueryParams::new()
                            .set_email(false)
                            .set_anchor_start(start)
                            .set_anchor_end(end)
                            .set_ignore_case(ignore_case),
                        &pattern);
                    match result {
                        Ok(got) => {
                            panic!("{}, select_userid({:?}) -> {}",
                                   handle.base, pattern,
                                   got.into_iter()
                                   .map(|c| c.fingerprint().to_string())
                                   .collect::<Vec<String>>()
                                   .join(", "));
                        }
                        Err(err) => {
                            match err.downcast_ref::<StoreError>() {
                                Some(StoreError::NoMatches(_)) => (),
                                _ => panic!("{}, select_userid({:?}) -> {}",
                                            handle.base, pattern, err),
                            }
                        }
                    }
                }

                // Search by exact email.
                let email = if let Ok(Some(email)) = userid.email() {
                    email
                } else {
                    // No email address.
                    continue;
                };

                // Search with the User ID using lookup_by_email.  This will
                // fail: a User ID that contains an email address is
                // never a valid email address.
                assert!(
                    backend.lookup_by_email(
                        str::from_utf8(userid.value()).expect("valid utf-8"))
                        .is_err(),
                    "{}, lookup_by_email({:?})", handle.base, userid);

                // Search by email.
                let got = backend.lookup_by_email(&email)
                    .expect(&format!("{}, lookup_by_email({:?})",
                                     handle.base, email));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, lookup_by_email({:?})", handle.base, userid);

                // Extract an interior substring (nor anchored at the
                // start or the end), and uppercase it.
                let pattern = &email[1..email.len() - 1];
                let pattern = pattern.to_uppercase();

                // grep removes all constraints so we should still
                // find it.
                let got = backend.grep_email(&pattern)
                    .expect(&format!("{}, grep_email({:?})",
                                     handle.base, pattern));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, grep_email({:?})", handle.base, pattern);

                // Now use an anchor at the start, or the end, ignore
                // case, or not.  This should not return any results;
                // the only one that should return any results is no
                // constraints, which we tested above.
                for (start, end, ignore_case) in
                    [(false, false, false),
                     //(false, false,  true),
                     (false,  true, false),
                     (false,  true,  true),
                     ( true, false, false),
                     ( true, false,  true),
                     ( true,  true, false),
                     ( true,  true,  true)]
                {
                    let result = backend.select_userid(
                        UserIDQueryParams::new()
                            .set_email(true)
                            .set_anchor_start(start)
                            .set_anchor_end(end)
                            .set_ignore_case(ignore_case),
                        &pattern);
                    match result {
                        Ok(got) => {
                            panic!("{}, select_userid({:?}) -> {}",
                                   handle.base, pattern,
                                   got.into_iter()
                                   .map(|c| c.fingerprint().to_string())
                                   .collect::<Vec<String>>()
                                   .join(", "));
                        }
                        Err(err) => {
                            match err.downcast_ref::<StoreError>() {
                                Some(StoreError::NoMatches(_)) => (),
                                _ => panic!("{}, select_userid({:?}) -> {}",
                                            handle.base, pattern, err),
                            }
                        }
                    }
                }



                // Search by domain.
                let domain = email.rsplit('@').next().expect("have an @");

                // Search with the User ID using lookup_by_email_domain.
                // This will fail: a User ID that contains an email
                // address is never a valid email address.
                assert!(
                    backend.lookup_by_email_domain(
                        str::from_utf8(userid.value()).expect("valid utf-8"))
                        .is_err(),
                    "{}, lookup_by_email_domain({:?})", handle.base, userid);
                // Likewise with the email address.
                assert!(
                    backend.lookup_by_email_domain(&email).is_err(),
                    "{}, lookup_by_email_domain({:?})", handle.base, email);

                // Search by domain.  We should find it.
                let got = backend.lookup_by_email_domain(&domain)
                    .expect(&format!("{}, lookup_by_email_domain({:?})",
                                     handle.base, domain));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, lookup_by_email_domain({:?})", handle.base, userid);

                // Uppercase it.  We should still find it.
                let pattern = domain.to_uppercase();
                let got = backend.lookup_by_email_domain(&pattern)
                    .expect(&format!("{}, lookup_by_email_domain({:?})",
                                     handle.base, pattern));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, lookup_by_email_domain({:?})", handle.base, pattern);

                // Extract an substring.  That we shouldn't find.
                let pattern = &domain[1..pattern.len() - 1];
                let result = backend.lookup_by_email_domain(pattern);
                match result {
                    Ok(got) => {
                        assert!(
                            got.into_iter().all(|c| {
                                c.fingerprint() != fpr
                            }),
                            "{}, lookup_by_email_domain({:?}, unexpectedly got {}",
                            handle.base, pattern, fpr);
                    }
                    Err(err) => {
                        match err.downcast_ref::<StoreError>() {
                            Some(StoreError::NoMatches(_)) => (),
                            _ => panic!("{}, lookup_by_email_domain({:?}) -> {}",
                                        handle.base, pattern, err),
                        }
                    }
                }
            }
        }

        // So far, the tests have been generic in the sense that we
        // look up what is there.  We now do some data set-specific
        // tests.

        let sort_vec = |mut v: Vec<_>| -> Vec<_> {
            v.sort();
            v
        };

        // alice and alice2 share a subkey.
        assert_eq!(
            sort_vec(backend.lookup_by_key(
                &"5989D7BE9908AE24799DF6CFBE678043781349F1"
                    .parse::<KeyHandle>().expect("valid"))
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>()),
            sort_vec(
                vec![
                    keyring::alice.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
                    keyring::alice2_adopted_alice.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
            ]));


        // ed's primary is also a subkey on the same certificate.
        assert_eq!(
            sort_vec(backend.lookup_by_key(
                &"0C346B2B6241263F64E9C7CF1EA300797258A74E"
                    .parse::<KeyHandle>().expect("valid"))
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>()),
            sort_vec(
                vec![
                    keyring::ed.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
            ]));



        // david has a subkey that doesn't have a binding signature,
        // but the backend is not supposed to check that.  (That
        // subkey is bound to carol.)
        assert_eq!(
            sort_vec(backend.lookup_by_key(
                &"CD22D4BD99FF10FDA11A83D4213DCB92C95346CE"
                    .parse::<KeyHandle>().expect("valid"))
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>()),
            sort_vec(
                vec![
                    keyring::carol.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
                    keyring::david.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
            ]));


        // Try a key that is not present.
        match backend.lookup_by_cert_fpr(
            &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                .parse::<Fingerprint>().expect("valid"))
        {
            Ok(cert) => panic!("lookup_by_cert_fpr(not present) -> {}",
                               cert.fingerprint()),
            Err(err) => {
                match err.downcast_ref::<StoreError>() {
                    Some(StoreError::NotFound(_)) => (),
                    _ => panic!("lookup_by_cert(not present) -> {}", err),
                }
            }
        }

        match backend.lookup_by_key(
            &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                .parse::<KeyHandle>().expect("valid"))
        {
            Ok(certs) => panic!("lookup_by_key(not present) -> {}",
                                certs
                                    .into_iter()
                                    .map(|c| c.fingerprint().to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")),
            Err(err) => {
                match err.downcast_ref::<StoreError>() {
                    Some(StoreError::NotFound(_)) => (),
                    _ => panic!("lookup_by_cert(not present) -> {}", err),
                }
            }
        }

        assert!(
            backend.lookup_by_key(
                &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                    .parse::<KeyHandle>().expect("valid"))
                .is_err());

        // Check puny code handling.

        // Look up the User ID using puny code.
        assert_eq!(
            backend.lookup_by_email("hans@xn--bcher-kva.tld")
                .expect("present")
                .len(),
            1);
        // And without puny code.
        assert_eq!(
            backend.lookup_by_email("hans@bücher.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        // A substring shouldn't match.
        assert_eq!(
            backend.lookup_by_email("hans@bücher.tl")
                .unwrap_or(Vec::new())
                .len(),
            0);

        // The same, but just look up by domain.
        assert_eq!(
            backend.lookup_by_email_domain("xn--bcher-kva.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        // And without puny code.
        assert_eq!(
            backend.lookup_by_email_domain("bücher.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);


        // Check that when looking up a subdomain, we don't get back
        // User IDs in a subdomain.
        assert_eq!(
            backend.lookup_by_email_domain("company.com")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::una.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        assert_eq!(
            backend.lookup_by_email_domain("sub.company.com")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::steve.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);


        // Check searching by domain.
        assert_eq!(
            sort_vec(backend.lookup_by_email_domain("verein.de")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>()),
            sort_vec(
                vec![
                    keyring::alice2_adopted_alice.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
                    keyring::carol.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
            ]));

        // It should be case insenitive.
        assert_eq!(
            sort_vec(backend.lookup_by_email_domain("VEREIN.DE")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>()),
            sort_vec(
                vec![
                    keyring::alice2_adopted_alice.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
                    keyring::carol.fingerprint
                        .parse::<Fingerprint>().expect("valid"),
            ]));
    }

    #[test]
    fn certd() -> Result<()> {
        use std::io::Read;

        // We expect 8 certificates.
        assert_eq!(keyring::certs.len(), 12);

        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        for cert in keyring::certs.iter() {
            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), certd_merge)
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
        }
        drop (certd);

        let certd = store::certd::CertD::open(&path).expect("exists");
        test_backend(certd);

        Ok(())
    }


    #[test]
    fn cert_store() -> Result<()> {
        use std::io::Read;

        // Sanity check how many certificates we read.
        assert_eq!(keyring::certs.len(), 12);

        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        for cert in keyring::certs.iter() {
            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), certd_merge)
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
        }
        drop(certd);

        let cert_store = CertStore::open(&path).expect("exists");
        test_backend(cert_store);

        Ok(())
    }

    #[test]
    fn cert_store_layered() -> Result<()> {
        use std::io::Read;

        assert_eq!(keyring::certs.len(), 12);

        // A certd for each certificate.
        let mut paths: Vec<tempfile::TempDir> = Vec::new();

        let mut cert_store = CertStore::empty();

        for cert in keyring::certs.iter() {
            let path = tempfile::tempdir()?;
            let certd = cert_d::CertD::with_base_dir(&path)
                .map_err(|err| {
                    let err = anyhow::Error::from(err)
                        .context(format!("While opening the certd {:?}", path));
                    print_error_chain(&err);
                    err
                })?;

            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), certd_merge)
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
            drop(certd);

            let certd = store::CertD::open(&path).expect("valid");
            cert_store.add_backend(Box::new(certd), AccessMode::Always);

            paths.push(path);
        }

        test_backend(cert_store);

        Ok(())
    }

    #[test]
    fn certs() -> Result<()> {
        use std::io::Read;

        assert_eq!(keyring::certs.len(), 12);

        let mut bytes = Vec::new();
        for cert in keyring::certs.iter() {
            let binary = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &binary,
                openpgp::armor::ReaderMode::VeryTolerant);
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));
        }

        let backend = store::Certs::from_bytes(&bytes)
            .expect("valid");
        test_backend(backend);

        Ok(())
    }

    #[test]
    fn certd_with_prefetch() -> Result<()> {
        use std::io::Read;

        assert_eq!(keyring::certs.len(), 12);

        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        for cert in keyring::certs.iter() {
            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), certd_merge)
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
        }
        drop (certd);

        let mut certd = store::CertD::open(&path).expect("exists");
        certd.prefetch_all();
        test_backend(certd);

        Ok(())
    }

    #[test]
    fn certs_with_prefetch() -> Result<()> {
        use std::io::Read;

        assert_eq!(keyring::certs.len(), 12);

        let mut bytes = Vec::new();
        for cert in keyring::certs.iter() {
            let binary = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &binary,
                openpgp::armor::ReaderMode::VeryTolerant);
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));
        }

        let mut backend = store::Certs::from_bytes(&bytes)
            .expect("valid");
        backend.prefetch_all();
        test_backend(backend);

        Ok(())
    }

    #[test]
    fn keyrings() -> Result<()> {
        let mut cert_store = CertStore::empty();

        let mut base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        base.push("tests");

        cert_store.add_keyrings(
            keyring::certs.iter().map(|c| {
                PathBuf::from(&base).join(c.filename)
            }))?;

        test_backend(cert_store);

        Ok(())
    }

    // Make sure that when we update a certificate, we are able to
    // find any new components and we are still able to find the old
    // components.
    fn test_store_update<'a, B>(mut backend: B) -> Result<()>
        where B: store::StoreUpdate<'a>
    {
        let p = &StandardPolicy::new();

        let signing_cert =
            Cert::from_bytes(&keyring::halfling_signing.bytes())
                .expect("valid");
        let fpr = signing_cert.fingerprint();

        // We expect a primary and two subkeys.
        assert_eq!(signing_cert.keys().count(), 3);
        let signing_vc = signing_cert.with_policy(p, None).expect("ok");
        let signing_fpr = signing_vc.keys().subkeys()
            .for_signing()
            .map(|ka| ka.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(signing_fpr.len(), 1);
        let signing_fpr = KeyHandle::from(
            signing_fpr.into_iter().next().expect("have one"));

        let auth_fpr = signing_vc.keys().subkeys()
            .for_authentication()
            .map(|ka| ka.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(auth_fpr.len(), 1);
        let auth_fpr = KeyHandle::from(
            auth_fpr.into_iter().next().expect("have one"));

        let encryption_cert =
            Cert::from_bytes(&keyring::halfling_encryption.bytes())
                .expect("valid");
        assert_eq!(fpr, encryption_cert.fingerprint());

        // We expect a primary and two subkeys.
        assert_eq!(encryption_cert.keys().count(), 3);
        let encryption_vc = encryption_cert.with_policy(p, None).expect("ok");
        let encryption_fpr = encryption_vc.keys().subkeys()
            .for_transport_encryption()
            .map(|ka| ka.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(encryption_fpr.len(), 1);
        let encryption_fpr = KeyHandle::from(
            encryption_fpr.into_iter().next().expect("have one"));

        assert_ne!(signing_fpr, encryption_fpr);

        let auth2_fpr = encryption_vc.keys().subkeys()
            .for_authentication()
            .map(|ka| ka.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(auth2_fpr.len(), 1);
        let auth2_fpr = KeyHandle::from(
            auth2_fpr.into_iter().next().expect("have one"));

        assert_eq!(auth_fpr, auth2_fpr);

        let merged_cert = signing_cert.clone()
            .merge_public(encryption_cert.clone()).expect("ok");

        let check = |backend: &B, have_enc: bool, cert: &Cert| {
            let r = backend.lookup_by_cert(&KeyHandle::from(fpr.clone())).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].to_cert().expect("ok"), cert);

            let r = backend.lookup_by_key(&signing_fpr).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].to_cert().expect("ok"), cert);

            let r = backend.lookup_by_key(&auth_fpr).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].to_cert().expect("ok"), cert);

            if have_enc {
                let r = backend.lookup_by_key(&encryption_fpr).unwrap();
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].to_cert().expect("ok"), cert);
            } else {
                assert!(backend.lookup_by_key(&encryption_fpr).is_err());
            }

            let r = backend.lookup_by_userid(
                &UserID::from("<regis@pup.com>")).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].to_cert().expect("ok"), cert);

            let r = backend.lookup_by_userid(
                &UserID::from("Halfling <signing@halfling.org>")).unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].to_cert().expect("ok"), cert);

            if have_enc {
                let r = backend.lookup_by_userid(
                    &UserID::from("Halfling <encryption@halfling.org>"))
                    .unwrap();
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].to_cert().expect("ok"), cert);
            } else {
                assert!(backend.lookup_by_key(&encryption_fpr).is_err());
            }
        };

        // Insert the signing certificate.
        backend.update(Cow::Owned(LazyCert::from(signing_cert.clone())))
            .expect("ok");
        check(&backend, false, &signing_cert);

        backend.update(Cow::Owned(LazyCert::from(encryption_cert.clone())))
            .expect("ok");
        check(&backend, true, &merged_cert);

        backend.update(Cow::Owned(LazyCert::from(signing_cert.clone())))
            .expect("ok");
        check(&backend, true, &merged_cert);

        Ok(())
    }

    // Test StoreUpdate::update for CertStore.
    #[test]
    fn test_store_update_cert_store() -> Result<()> {
        let path = tempfile::tempdir()?;
        let cert_store = CertStore::open(&path).expect("exists");
        test_store_update(cert_store)
    }

    // Test StoreUpdate::update for Certs.
    #[test]
    fn test_store_update_certs() -> Result<()> {
        let certs = Certs::empty();
        test_store_update(certs)
    }
}

