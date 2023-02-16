//! A certificate store abstraction.
//!
//! This crates provides a unified interface for different certificate
//! stores via the [`Store`] trait.  It also provides a number of
//! helper functions and data structures, like [`UserIDIndex`] to help
//! implement this functionality.
//!
//! [`UserIDIndex`]: store::UserIDIndex
//!
//! The [`CertDB`] data structure combines multiple certificate
//! backends in a transparent way to users.
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::packet::UserID;

#[macro_use] mod log;
#[macro_use] mod macros;

pub mod store;
pub use store::Store;
pub use store::StoreUpdate;
mod cert_db;
pub use cert_db::CertDB;
pub use cert_db::AccessMode;

mod lazy_cert;
pub use lazy_cert::LazyCert;

const TRACE: bool = false;

/// Prints the error and causes, if any.
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

    use std::str;

    use anyhow::Context;

    use openpgp::Fingerprint;
    use openpgp::KeyHandle;
    use openpgp::KeyID;

    use store::StoreError;
    use store::UserIDQueryParams;

    include!("../tests/keyring.rs");

    fn test_backend<'a, B>(backend: B)
        where B: Store<'a>
    {
        // Check Store::list.
        {
            let mut got: Vec<Fingerprint> = backend.list().collect();
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
                = backend.iter().map(|c| c.fingerprint()).collect();
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
            let got = backend.by_cert_fpr(&fpr).expect("present");
            assert_eq!(got.fingerprint(), fpr,
                       "{}, by_cert_fpr, primary", handle.base);

            // Look up by subkey and make sure we don't get cert.
            // Note: if a subkey is also a primary key (as is the case
            // for the ed certificate), then we'll get a certificate
            // back.
            for sk in cert.keys().subkeys() {
                match backend.by_cert_fpr(&sk.fingerprint()) {
                    Ok(got) => {
                        // The subkey could be a primary key for a
                        // different certificate.  So, make sure it is
                        // not
                        assert!(
                            keyring::certs.iter().any(|c| {
                                c.fingerprint.parse::<Fingerprint>().unwrap()
                                    == got.fingerprint()
                            }),
                            "{}, by_cert_fpr, subkey, unexpectedly got {}",
                            handle.base, got.fingerprint());
                    }
                    Err(err) => {
                        match err.downcast_ref::<StoreError>() {
                            Some(StoreError::NotFound(_)) => (),
                            _ => panic!("Unexpected failure: {}", err),
                        }
                    },
                }
            }

            // Check by_cert using key ids.
            let got = backend.by_cert(&KeyHandle::from(&keyid))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, by_cert, keyid, primary", handle.base);

            // Look up by subkey.  This will only return something if
            // the subkey also happens to be a primary key.
            for sk in cert.keys().subkeys() {
                match backend.by_cert(&KeyHandle::from(sk.keyid())) {
                    Ok(got) => {
                        // Make sure subkey is also a primary key.
                        for got in got.into_iter() {
                            assert!(
                                keyring::certs.iter().any(|c| {
                                    c.fingerprint.parse::<Fingerprint>()
                                        .unwrap()
                                        == got.fingerprint()
                                }),
                                "{}, by_cert_fpr, subkey, unexpectedly got {}",
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

            // Check by_key using fingerprints.
            let got = backend.by_key(&KeyHandle::from(fpr.clone()))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, by_key, with fingerprint, primary", handle.base);

            // Look up by subkey and make sure we get cert.
            for sk in cert.keys().subkeys() {
                let got = backend.by_key(&KeyHandle::from(sk.fingerprint()))
                    .expect("present");
                assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                        "{}, by_key, with fingerprint, subkey", handle.base);
            }


            // Check by_key using keyids.
            let got = backend.by_key(&KeyHandle::from(keyid.clone()))
                .expect("present");
            assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                    "{}, by_key, with keyid, primary", handle.base);

            // Look up by subkey and make sure we get cert.
            for sk in cert.keys().subkeys() {
                let got = backend.by_key(&KeyHandle::from(sk.keyid()))
                    .expect("present");
                assert!(got.into_iter().any(|c| c.fingerprint() == fpr),
                        "{}, by_key, with keyid, subkey", handle.base);
            }


            // Check look up by User ID address by querying for each
            // User ID, email, domain, etc.
            for ua in cert.userids() {
                let userid = ua.userid();

                // Search by exact user id.
                let got = backend.by_userid(userid)
                    .expect(&format!("{}, by_userid({:?})",
                                     handle.base, userid));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, by_userid({:?})", handle.base, userid);

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

                // Search with the User ID using by_email.  This will
                // fail: a User ID that contains an email address is
                // never a valid email address.
                assert!(
                    backend.by_email(
                        str::from_utf8(userid.value()).expect("valid utf-8"))
                        .is_err(),
                    "{}, by_email({:?})", handle.base, userid);

                // Search by email.
                let got = backend.by_email(&email)
                    .expect(&format!("{}, by_email({:?})",
                                     handle.base, email));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, by_email({:?})", handle.base, userid);

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

                // Search with the User ID using by_email_domain.
                // This will fail: a User ID that contains an email
                // address is never a valid email address.
                assert!(
                    backend.by_email_domain(
                        str::from_utf8(userid.value()).expect("valid utf-8"))
                        .is_err(),
                    "{}, by_email_domain({:?})", handle.base, userid);
                // Likewise with the email address.
                assert!(
                    backend.by_email_domain(&email).is_err(),
                    "{}, by_email_domain({:?})", handle.base, email);

                // Search by domain.  We should find it.
                let got = backend.by_email_domain(&domain)
                    .expect(&format!("{}, by_email_domain({:?})",
                                     handle.base, domain));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, by_email_domain({:?})", handle.base, userid);

                // Uppercase it.  We should still find it.
                let pattern = domain.to_uppercase();
                let got = backend.by_email_domain(&pattern)
                    .expect(&format!("{}, by_email_domain({:?})",
                                     handle.base, pattern));
                assert!(
                    got.into_iter().any(|c| {
                        c.userids().any(|u| &u == userid)
                    }),
                    "{}, by_email_domain({:?})", handle.base, pattern);

                // Extract an substring.  That we shouldn't find.
                let pattern = &domain[1..pattern.len() - 1];
                let result = backend.by_email_domain(pattern);
                match result {
                    Ok(got) => {
                        assert!(
                            got.into_iter().all(|c| {
                                c.fingerprint() != fpr
                            }),
                            "{}, by_email_domain({:?}, unexpectedly got {}",
                            handle.base, pattern, fpr);
                    }
                    Err(err) => {
                        match err.downcast_ref::<StoreError>() {
                            Some(StoreError::NoMatches(_)) => (),
                            _ => panic!("{}, by_email_domain({:?}) -> {}",
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
            sort_vec(backend.by_key(
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
            sort_vec(backend.by_key(
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
            sort_vec(backend.by_key(
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
        match backend.by_cert_fpr(
            &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                .parse::<Fingerprint>().expect("valid"))
        {
            Ok(cert) => panic!("by_cert_fpr(not present) -> {}",
                               cert.fingerprint()),
            Err(err) => {
                match err.downcast_ref::<StoreError>() {
                    Some(StoreError::NotFound(_)) => (),
                    _ => panic!("by_cert(not present) -> {}", err),
                }
            }
        }

        match backend.by_key(
            &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                .parse::<KeyHandle>().expect("valid"))
        {
            Ok(certs) => panic!("by_key(not present) -> {}",
                                certs
                                    .into_iter()
                                    .map(|c| c.fingerprint().to_string())
                                    .collect::<Vec<String>>()
                                    .join(", ")),
            Err(err) => {
                match err.downcast_ref::<StoreError>() {
                    Some(StoreError::NotFound(_)) => (),
                    _ => panic!("by_cert(not present) -> {}", err),
                }
            }
        }

        assert!(
            backend.by_key(
                &"0123 4567 89AB CDEF 0123 4567 89AB CDEF"
                    .parse::<KeyHandle>().expect("valid"))
                .is_err());

        // Check puny code handling.

        // Look up the User ID using puny code.
        assert_eq!(
            backend.by_email("hans@xn--bcher-kva.tld")
                .expect("present")
                .len(),
            1);
        // And without puny code.
        assert_eq!(
            backend.by_email("hans@bücher.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        // A substring shouldn't match.
        assert_eq!(
            backend.by_email("hans@bücher.tl")
                .unwrap_or(Vec::new())
                .len(),
            0);

        // The same, but just look up by domain.
        assert_eq!(
            backend.by_email_domain("xn--bcher-kva.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        // And without puny code.
        assert_eq!(
            backend.by_email_domain("bücher.tld")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::hans_puny_code.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);


        // Check that when looking up a subdomain, we don't get back
        // User IDs in a subdomain.
        assert_eq!(
            backend.by_email_domain("company.com")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::una.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);
        assert_eq!(
            backend.by_email_domain("sub.company.com")
                .expect("present")
                .into_iter()
                .map(|c| c.fingerprint())
                .collect::<Vec<Fingerprint>>(),
            vec![ keyring::steve.fingerprint
                  .parse::<Fingerprint>().expect("valid") ]);


        // Check searching by domain.
        assert_eq!(
            sort_vec(backend.by_email_domain("verein.de")
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
            sort_vec(backend.by_email_domain("VEREIN.DE")
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
        use openpgp_cert_d as cert_d;

        // We expect 8 certificates.
        assert_eq!(keyring::certs.len(), 10);

        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        for cert in keyring::certs.iter() {
            // certd.insert doesn't do a merge.  That's okay, just
            // skip this certificate.
            if cert.base == "alice2" {
                // We prefer alice2-adopted-alice.
                continue;
            }

            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), |new, disk| {
                    assert!(disk.is_none());

                    Ok(new)
                })
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
    fn certdb() -> Result<()> {
        use std::io::Read;
        use openpgp_cert_d as cert_d;

        // Sanity check how many certificates we read.
        assert_eq!(keyring::certs.len(), 10);

        let path = tempfile::tempdir()?;
        let certd = cert_d::CertD::with_base_dir(&path)
            .map_err(|err| {
                let err = anyhow::Error::from(err)
                    .context(format!("While opening the certd {:?}", path));
                print_error_chain(&err);
                err
            })?;

        for cert in keyring::certs.iter() {
            // certd.insert doesn't do a merge.  That's okay, just
            // skip this certificate.
            if cert.base == "alice2" {
                // We prefer alice2-adopted-alice.
                continue;
            }

            let bytes = cert.bytes();
            let mut reader = openpgp::armor::Reader::from_bytes(
                &bytes,
                openpgp::armor::ReaderMode::VeryTolerant);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)
                .expect(&format!("{}", cert.base));

            certd
                .insert(bytes.into_boxed_slice(), |new, disk| {
                    assert!(disk.is_none());

                    Ok(new)
                })
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
        }
        drop (certd);

        let certdb = CertDB::open(&path).expect("exists");
        test_backend(certdb);

        Ok(())
    }

    #[test]
    fn certdb_layered() -> Result<()> {
        use std::io::Read;
        use openpgp_cert_d as cert_d;

        assert_eq!(keyring::certs.len(), 10);

        // A certd for each certificate.
        let mut paths: Vec<tempfile::TempDir> = Vec::new();

        let mut certdb = CertDB::empty();

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
                .insert(bytes.into_boxed_slice(), |new, disk| {
                    assert!(disk.is_none());

                    Ok(new)
                })
                .with_context(|| {
                    format!("{} ({})", cert.base, cert.fingerprint)
                })
                .expect("can insert");
            drop(certd);

            let certd = store::CertD::open(&path).expect("valid");
            certdb.add_backend(Box::new(certd), AccessMode::Always);

            paths.push(path);
        }

        test_backend(certdb);

        Ok(())
    }

    #[test]
    fn certs() -> Result<()> {
        use std::io::Read;

        assert_eq!(keyring::certs.len(), 10);

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
}
