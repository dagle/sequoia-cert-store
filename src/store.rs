use std::borrow::Cow;
use std::str;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::Cert;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

mod userid_index;
pub use userid_index::UserIDIndex;

pub mod certd;
pub use certd::CertD;

pub mod certs;
pub use certs::Certs;

pub mod keyserver;
pub use keyserver::KeyServer;

pub mod pep;
pub use pep::Pep;

use super::TRACE;

use crate::LazyCert;

#[derive(Debug, Clone)]
pub struct UserIDQueryParams {
    anchor_start: bool,
    anchor_end: bool,
    email: bool,
    ignore_case: bool,
}

impl UserIDQueryParams {
    /// Returns a new `UserIDQueryParams`.
    ///
    /// By default, the query is configured to perform an exact match
    /// on the User ID.  That is, the pattern must match the start and
    /// end of the User ID, and case is considered significant.
    pub fn new() -> Self {
        Self {
            anchor_start: true,
            anchor_end: true,
            email: false,
            ignore_case: false,
        }
    }

    /// Sets whether the pattern must match the start of the User ID
    /// or email address.
    pub fn set_anchor_start(&mut self, anchor_start: bool) -> &mut Self {
        self.anchor_start = anchor_start;
        self
    }

    /// Returns whether the pattern must match the start of the User
    /// ID or email address.
    pub fn anchor_start(&self) -> bool {
        self.anchor_start
    }

    /// Sets whether the pattern must match the end of the User
    /// ID or email address.
    pub fn set_anchor_end(&mut self, anchor_end: bool) -> &mut Self {
        self.anchor_end = anchor_end;
        self
    }

    /// Returns whether the pattern must match the end of the User
    /// ID or email address.
    pub fn anchor_end(&self) -> bool {
        self.anchor_end
    }

    /// Sets whether the pattern must match the User ID or the
    /// normalized email address.
    ///
    /// The email address to check the pattern against is extracted
    /// from the User ID using [`UserID::email_normalized`].
    ///
    /// Note: the pattern is *not* normalized, even if the anchors are
    /// set.  If you want to search by email address you need to
    /// normalize it your yourself.
    ///
    /// [`UserID::email_normalized`]: https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/packet/prelude/struct.UserID.html#method.email_normalized
    pub fn set_email(&mut self, email: bool) -> &mut Self {
        self.email = email;
        self
    }

    /// Returns whether the pattern must match the User ID or the
    /// normalized email address.
    ///
    /// See [`UserIDQueryParams::set_email`] for more details.
    pub fn email(&self) -> bool {
        self.email
    }

    /// Sets whether to ignore the case when matching the User ID or
    /// email address.
    ///
    /// Uses the empty local.
    ///
    /// When matching an email address, the domain is always matched
    /// in a case insensitive manner.  The localpart, however, is
    /// matched in a case sensitive manner by default.
    pub fn set_ignore_case(&mut self, ignore_case: bool) -> &mut Self {
        self.ignore_case = ignore_case;
        self
    }

    /// Returns whether to ignore the case when matching the User ID
    /// or email address.
    ///
    /// See [`UserIDQueryParams::set_ignore_case`] for more details.
    pub fn ignore_case(&self) -> bool {
        self.ignore_case
    }

    /// Checks that the User ID satisfies the constraints.
    pub fn check(&self, userid: &UserID, pattern: &str) -> bool {
        tracer!(TRACE, "UserIDQueryParams::check");

        // XXX: If you change this function,
        // UserIDIndex::select_userid contains similar code.  Update
        // that too.
        match self {
            UserIDQueryParams {
                anchor_start: true,
                anchor_end: true,
                email: false,
                ignore_case: false,
            } => {
                // Exact User ID match.
                userid.value() == pattern.as_bytes()
            }

            UserIDQueryParams {
                anchor_start: true,
                anchor_end: true,
                email: true,
                ignore_case: false,
            } => {
                // Exact email match.
                if let Ok(Some(email)) = userid.email_normalized() {
                    email == pattern
                } else {
                    false
                }
            }

            UserIDQueryParams {
                anchor_start,
                anchor_end,
                email,
                ignore_case,
            } => {
                t!("Considering if {:?} matches {:?} \
                    (anchors: {}, {}, ignore case: {})",
                   pattern, userid, anchor_start, anchor_end, ignore_case);

                // Substring search.
                let mut userid = if *email {
                    if let Ok(Some(email)) = userid.email_normalized() {
                        email
                    } else {
                        t!("User ID does not contain a valid email address");
                        return false;
                    }
                } else {
                    if let Ok(userid)
                        = String::from_utf8(userid.value().to_vec())
                    {
                        userid
                    } else {
                        t!("User ID is not UTF-8 encoded");
                        return false;
                    }
                };

                if *ignore_case {
                    userid = userid.to_lowercase();
                }

                let mut pattern = pattern;
                let _pattern;
                if *ignore_case {
                    // Convert to lowercase without tailoring,
                    // i.e. without taking any locale into account.
                    // See:
                    //
                    //  - https://www.w3.org/International/wiki/Case_folding
                    //  - https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
                    //  - http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G33992
                    _pattern = pattern.to_lowercase();
                    pattern = &_pattern[..];
                }

                if match (*anchor_start, *anchor_end) {
                    (true, true) => userid == pattern,
                    (true, false) => userid.starts_with(pattern),
                    (false, true) => userid.ends_with(pattern),
                    (false, false) => userid.contains(pattern),
                }
                {
                    t!("*** {:?} matches {:?} (anchors: {}, {})",
                       pattern, userid, *anchor_start, anchor_end);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Checks that at least one User ID satisfies the constraints.
    pub fn check_lazy_cert(&self, cert: &LazyCert, pattern: &str) -> bool {
        cert.userids().any(|userid| self.check(&userid, pattern))
    }

    /// Checks that at least one User ID satisfies the constraints.
    pub fn check_cert(&self, cert: &Cert, pattern: &str) -> bool {
        cert.userids().any(|ua| self.check(ua.userid(), pattern))
    }

    /// Checks that at least one User ID satisfies the constraints.
    pub fn check_valid_cert(&self, vc: &ValidCert, pattern: &str) -> bool {
        vc.userids().any(|ua| self.check(ua.userid(), pattern))
    }

    /// Returns whether the supplied email address is actually a valid
    /// email address.
    ///
    /// If it is valid, returns the normalized email address.
    pub fn is_email(email: &str) -> Result<String> {
        let email_check = UserID::from(format!("<{}>", email));
        match email_check.email() {
            Ok(Some(email_check)) => {
                if email != email_check {
                    return Err(StoreError::InvalidEmail(
                        email.to_string(), None).into());
                }
            }
            Ok(None) => {
                return Err(StoreError::InvalidEmail(
                    email.to_string(), None).into());
            }
            Err(err) => {
                return Err(StoreError::InvalidEmail(
                    email.to_string(), Some(err)).into());
            }
        }

        match UserID::from(&email[..]).email_normalized() {
            Err(err) => {
                Err(StoreError::InvalidEmail(
                    email.to_string(), Some(err)).into())
            }
            Ok(None) => {
                Err(StoreError::InvalidEmail(
                    email.to_string(), None).into())
            }
            Ok(Some(email)) => {
                Ok(email)
            }
        }
    }

    /// Returns whether the supplied domain address is actually a
    /// valid domain for an email address.
    ///
    /// Returns the normalized domain.
    pub fn is_domain(domain: &str) -> Result<String> {
        let localpart = "user@";
        let email = format!("{}{}", localpart, domain);
        let email = Self::is_email(&email)?;

        // We get the normalized email address back.  Chop off the
        // username and the @.
        assert!(email.starts_with(localpart));
        Ok(email[localpart.len()..].to_string())
    }
}

/// [`Store`] specific error codes.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// No certificate was found.
    #[error("{0} was not found")]
    NotFound(KeyHandle),

    /// No certificate matches the search criteria.
    #[error("No certificates matched {0}")]
    NoMatches(String),

    /// The email address does not appear to be a valid email address.
    #[error("{0:?} does not appear to be a valid email address")]
    InvalidEmail(String, #[source] Option<anyhow::Error>),
}

/// Status messages.
///
/// Status messages sent by [`StatusListener::update`].
///
/// The transaction id allows messages to be grouped together.  For
/// instance, `LookupStarted` will return a new transaction id and
/// further messages related to that lookup including `LookupFinished`
/// and `LookupFailed` will use the same transaction id.
#[non_exhaustive]
#[derive(Debug)]
pub enum StatusUpdate<'a, 'c: 'rc, 'rc> {
    /// Sent when a lookup is starting.
    ///
    /// usize is the transaction id.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// `KeyHandle` is what is being looked up.
    ///
    /// The last `&str` is a short human-readable message describing
    /// the look up.
    LookupStarted(usize, &'a str, &'a KeyHandle, Option<&'a str>),

    /// Sent while a lookup is on-going.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// `KeyHandle` is what was being looked up.
    ///
    /// The last `&str` is a short human-readable message describing
    /// something that happened, e.g., "WKD returned FPR", etc.
    LookupStatus(usize, &'a str, &'a KeyHandle, &'a str),

    /// Sent when a lookup has been successful.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// `KeyHandle` is what was being looked up.
    ///
    /// The certificates are the returned results.
    ///
    /// The last `&str` is a short human-readable message describing
    /// what happened, e.g., "found in cache", etc.
    LookupFinished(usize, &'a str, &'a KeyHandle,
                   &'a [Cow<'rc, LazyCert<'c>>], Option<&'a str>),

    /// Sent when a lookup has failed.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// `KeyHandle` is what was being looked up.
    ///
    /// The error is the reason that the lookup failed.  A backend
    /// should set this to `None` if no certificate was present.
    LookupFailed(usize, &'a str, &'a KeyHandle, Option<&'a anyhow::Error>),

    /// Sent when a search is started.
    ///
    /// usize is the transaction id.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// The second `&str` is the pattern being searched for.
    ///
    /// The last `&str` is a short human-readable message describing
    /// what is being looked up.
    SearchStarted(usize, &'a str, &'a str, Option<&'a str>),

    /// Sent while a search is on-going.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// The second `&str` is the pattern being searched for.
    ///
    /// The last `&str` is a short human-readable message describing
    /// something that happened, e.g., "WKD returned FPR", etc.
    SearchStatus(usize, &'a str, &'a str, &'a str),

    /// Sent when a search is successful.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// The second `&str` is the pattern being searched for.
    ///
    /// The certificates are the returned results.
    ///
    /// The last `&str` is a short human-readable message describing
    /// what happened, e.g., "found in cache", "found 5 matching
    /// certificates", etc.
    SearchFinished(usize, &'a str, &'a str, &'a [Cow<'rc, LazyCert<'c>>],
                   Option<&'a str>),

    /// Sent whenever something has been lookup successfully.
    ///
    /// usize is the transaction id.  It will match the transaction id
    /// sent in the `LookupStart` message.
    ///
    /// The first `&str` is a short human-readable description of the
    /// backend.
    ///
    /// The second `&str` is the pattern being searched for.
    ///
    /// The error is the reason that the search failed.  A backend
    /// should set this to `None` if no matching certificate was
    /// found.
    SearchFailed(usize, &'a str, &'a str, Option<&'a anyhow::Error>),
}

impl<'a, 'c: 'rc, 'rc> std::fmt::Display for StatusUpdate<'a, 'c, 'rc> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>)
        -> std::result::Result<(), std::fmt::Error>
    {
        use StatusUpdate::*;

        match self {
            LookupStarted(_tx, backend, kh, msg) => {
                if let Some(msg) = msg {
                    write!(fmt, "{}: Looking up {}: {}...",
                           backend, kh, msg)
                } else {
                    write!(fmt, "{}: Looking up {}...",
                           backend, kh)
                }
            }
            LookupStatus(_tx, backend, kh, msg) => {
                write!(fmt, "{}: Looking up {}: {}",
                       backend, kh, msg)
            }
            LookupFinished(_tx, backend, kh, results, msg) => {
                if let Some(msg) = msg {
                    write!(fmt, "{}: Looking up {}, returned {} results: {}",
                           backend, kh, results.len(), msg)
                } else {
                    write!(fmt, "{}: Looking up {}, returned {} results",
                           backend, kh, results.len())
                }
            }
            LookupFailed(_tx, backend, kh, err) => {
                if let Some(err) = err {
                    write!(fmt, "{}: Looking up {}, failed: {}",
                           backend, kh, err)
                } else {
                    write!(fmt, "{}: Looking up {}, returned no results",
                           backend, kh)
                }
            }

            SearchStarted(_tx, backend, pattern, msg) => {
                if let Some(msg) = msg {
                    write!(fmt, "{}: Searching for {:?}: {}...",
                           backend, pattern, msg)
                } else {
                    write!(fmt, "{}: Searching for {:?}...",
                           backend, pattern)
                }
            }
            SearchStatus(_tx, backend, pattern, msg) => {
                write!(fmt, "{}: Searching for {:?}: {}",
                       backend, pattern, msg)
            }
            SearchFinished(_tx, backend, pattern, results, msg) => {
                if let Some(msg) = msg {
                    write!(fmt, "{}: Searching for {:?}, returned {} results: {}",
                           backend, pattern, results.len(), msg)
                } else {
                    write!(fmt, "{}: Searching for {:?}, returned {} results",
                           backend, pattern, results.len())
                }
            }
            SearchFailed(_tx, backend, pattern, err) => {
                if let Some(err) = err {
                    write!(fmt, "{}: Searching for {:?} failed: {}",
                           backend, pattern, err)
                } else {
                    write!(fmt, "{}: Searching for {:?}, returned no results",
                           backend, pattern)
                }
            }
        }
    }
}


/// A callback mechanism to indicate what a backend is doing.
///
/// We use an enum instead of a separate function for each message so
/// that a naive listener can just print each message to stdout.
///
/// This is primarily interesting for backends like a keyserver.
///
/// Currently, backends are not required to implement this trait.  In
/// fact [`KeyServer`] is the only backend that implements it.  A
/// caller can add a listener to a `KeyServer` using
/// [`KeyServer::add_listener`].
pub trait StatusListener {
    /// A status update.
    fn update(&self, status: &StatusUpdate);
}

/// Returns certificates from a backing store.
pub trait Store<'a> {
    /// Returns the certificates whose fingerprint matches the handle.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Returns the certificate with the specified fingerprint, if any.
    ///
    /// Returns [`StoreError::NotFound`] if the certificate is not found.
    ///
    /// The default implementation is implemented in terms of
    /// [`Store::lookup_by_cert`].
    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        let kh = KeyHandle::from(fingerprint.clone());

        self.lookup_by_cert(&kh)
            .and_then(|v| {
                assert!(v.len() <= 1);
                v.into_iter().next()
                    .ok_or(StoreError::NotFound(kh).into())
            })
    }

    /// Returns certificates that have a key with the specified
    /// handle, if any.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is not found.
    ///
    /// Note: even if you pass a fingerprint, this may return multiple
    /// certificates as the same subkey may be attached to multiple
    /// certificates.
    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Returns certificates that have a User ID matching the
    /// specified pattern according to the query parameters.
    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Performs an exact match on the User ID.
    ///
    /// The pattern is anchored, and the match is case sensitive.
    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.select_userid(
            &UserIDQueryParams::new()
                .set_email(false)
                .set_anchor_start(true)
                .set_anchor_end(true)
                .set_ignore_case(false),
            &String::from_utf8(userid.value().to_vec())?)
    }

    /// Performs a case insenitive, substring match on the User ID.
    ///
    /// The pattern is not anchored, and it is matched case
    /// insensitively.
    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.select_userid(
            &UserIDQueryParams::new()
                .set_email(false)
                .set_anchor_start(false)
                .set_anchor_end(false)
                .set_ignore_case(true),
            pattern)
    }

    /// Returns certificates that have a User ID with the specified
    /// email address.
    ///
    /// The pattern is interpreted as an email address.  It is first
    /// normalized, and then matched against the normalized email
    /// address, it is anchored, and the match is case sensitive.
    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let userid = crate::email_to_userid(&email)?;
        let email = userid.email_normalized()?.expect("have one");

        self.select_userid(
            &UserIDQueryParams::new()
                .set_email(true)
                .set_anchor_start(true)
                .set_anchor_end(true)
                .set_ignore_case(false),
            &email)
    }

    /// Performs a case insenitive, substring match on the normalized
    /// email address.
    ///
    /// The pattern is matched against the normalized email address,
    /// it is not anchored, and it is matched case insensitively.  The
    /// pattern itself is *not* normalized.
    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.select_userid(
            &UserIDQueryParams::new()
                .set_email(true)
                .set_anchor_start(false)
                .set_anchor_end(false)
                .set_ignore_case(true),
            pattern)
    }

    /// Returns certificates that have User ID with an email address
    /// from the specified domain.
    ///
    /// The pattern is interpreted as a domain address.  It is first
    /// normalized, and then matched against the normalized email
    /// address, it is anchored, and the match is case sensitive.
    ///
    /// `domain` must be a bare domain, like `example.org`; it should
    /// not start with an `@`.  This does not match subdomains.  That
    /// is, it will match `alice@foo.bar.com` when searching for
    /// `bar.com`.
    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        let localpart = "localpart";
        let email = format!("{}@{}", localpart, domain);
        let userid = crate::email_to_userid(&email)?;
        let email = userid.email_normalized()?.expect("have one");
        let domain = &email[email.rfind('@').expect("have an @")..];

        self.select_userid(
            &UserIDQueryParams::new()
                .set_email(true)
                .set_anchor_start(false)
                .set_anchor_end(true)
                .set_ignore_case(false),
            domain)
    }

    /// Lists all of the certificates.
    ///
    /// If a backend is not able to enumerate all the certificates,
    /// then it should return those that it knows about.  For
    /// instance, some keyservers allow certificates to be looked up
    /// by fingerprint, but not to enumerate all of the certificates.
    /// Thus, a user must not assume that if a certificate is not
    /// returned by this function, it cannot be found by name.
    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b>;

    /// Returns all of the certificates.
    ///
    /// The default implementation is implemented in terms of
    /// [`Store::fingerprints`] and [`Store::lookup_by_cert_fpr`].  Many backends
    /// will be able to do this more efficiently.
    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        Box::new(self.fingerprints()
            .filter_map(|fpr| {
                self.lookup_by_cert_fpr(&fpr).ok()
            }))
    }

    /// Prefills the cache.
    ///
    /// Prefilling the cache makes sense when you plan to examine most
    /// certificates.  It doesn't make sense if you are just
    /// authenticating a single or a few bindings.
    ///
    /// This function may be multi-threaded.
    ///
    /// Errors should be silently ignored and propagated when the
    /// operation in question is executed directly.
    fn prefetch_all(&mut self) {
    }

    /// Prefetches some certificates.
    ///
    /// Prefilling the cache makes sense when you plan to examine some
    /// certificates in the near future.
    ///
    /// This interface is useful as it allows batching, which may be
    /// more efficient, especially when the certificates are accessed
    /// over the network.  And, the function may be multi-threaded.
    ///
    /// Errors should be silently ignored and propagated when the
    /// operation in question is executed directly.
    fn prefetch_some(&mut self, certs: Vec<KeyHandle>) {
        let _ = certs;
    }
}

// The references in Store need a different lifetime from the contents
// of the Box.  Otherwise, a `Backend` that is a `&Box<Store>` would
// create a self referential data structure.
impl<'a: 't, 't, T> Store<'a> for Box<T>
where T: Store<'a> + ?Sized + 't
{
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        self.as_ref().lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().lookup_by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        self.as_ref().select_userid(query, pattern)
    }

    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().lookup_by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().grep_userid(pattern)
    }

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().lookup_by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().grep_email(pattern)
    }

    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().lookup_by_email_domain(domain)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        self.as_ref().fingerprints()
    }

    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        self.as_ref().certs()
    }

    fn prefetch_all(&mut self) {
        self.as_ref().prefetch_all()
    }

    fn prefetch_some(&mut self, certs: Vec<KeyHandle>) {
        self.as_ref().prefetch_some(certs)
    }
}

impl<'a: 't, 't, T> Store<'a> for &'t T
where T: Store<'a> + ?Sized
{
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        (*self).lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).lookup_by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        (*self).select_userid(query, pattern)
    }

    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).lookup_by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).grep_userid(pattern)
    }

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).lookup_by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).grep_email(pattern)
    }

    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).lookup_by_email_domain(domain)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        (*self).fingerprints()
    }

    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        (*self).certs()
    }
}

impl<'a: 't, 't, T> Store<'a> for &'t mut T
where T: Store<'a> + ?Sized
{
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        (**self).lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).lookup_by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        (**self).select_userid(query, pattern)
    }

    fn lookup_by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).lookup_by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).grep_userid(pattern)
    }

    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).lookup_by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).grep_email(pattern)
    }

    fn lookup_by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).lookup_by_email_domain(domain)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        (**self).fingerprints()
    }

    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        (**self).certs()
    }

    fn prefetch_all(&mut self) {
        (**self).prefetch_all()
    }

    fn prefetch_some(&mut self, certs: Vec<KeyHandle>) {
        (**self).prefetch_some(certs)
    }
}

/// Merges two certificates.
///
/// This is primarily useful as the `merge_strategy` callback to
/// [`StoreUpdate::update_by`].
pub trait MergeCerts<'a: 'ra, 'ra> {
    /// Merges two certificates.
    ///
    /// This is primarily useful as the `merge_strategy` callback to
    /// [`StoreUpdate::update_by`].
    ///
    /// The default implementation merges the two certificates using
    /// [`Cert::merge_public`].  This means that any secret key
    /// material in `disk` is preserved, any secret key material in
    /// `new` is ignored, and unhashed subpacket areas are merged.
    fn merge_public<'b, 'rb>(&mut self,
                             new: Cow<'ra, LazyCert<'a>>,
                             disk: Option<Cow<'rb, LazyCert<'b>>>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        if let Some(disk) = disk {
            let merged = disk.as_cert()?
                .merge_public(new.into_owned().into_cert()?)?;
            Ok(Cow::Owned(LazyCert::from(merged)))
        } else {
            if new.is_tsk() {
                Ok(Cow::Owned(LazyCert::from(new.into_owned().into_cert()?
                                             .strip_secret_key_material())))
            } else {
                Ok(new)
            }
        }
    }
}

impl<'a: 'ra, 'ra> MergeCerts<'a, 'ra> for () {
}

/// Provides an interface to update a backing store.
pub trait StoreUpdate<'a>: Store<'a> {
    /// Insert a certificate.
    ///
    /// This uses the default implementation of [`MergeCerts`] to
    /// merge the certificate with any existing certificate.
    fn update(&mut self, cert: Cow<LazyCert<'a>>) -> Result<()> {
        self.update_by(cert, &mut ())?;

        Ok(())
    }

    /// Inserts a certificate into the store.
    ///
    /// Inserts a certificate into the store and uses `merge_strategy`
    /// to merge it with the existing certificate, if any.
    ///
    /// Unless there is an error, you must call `merge_strategy`.
    /// This is the case even if the certificate is not on the
    /// backend.  In that case, you must pass `None` for the on-disk
    /// version.  This allows `merge_strategy` to generate statistics,
    /// and to modify the certificate before it is saved, e.g., by
    /// stripping third-party certifications.
    ///
    /// To use the default merge strategy, either call
    /// [`StoreUpdate::update`] directly, or pass `&mut ()`.
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>;
}

impl<'a: 't, 't, T> StoreUpdate<'a> for Box<T>
where T: StoreUpdate<'a> + ?Sized + 't
{
    fn update(&mut self, cert: Cow<LazyCert<'a>>) -> Result<()> {
        self.as_mut().update(cert)
    }

    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        self.as_mut().update_by(cert, merge_strategy)
    }
}

impl<'a: 't, 't, T> StoreUpdate<'a> for &'t mut T
where T: StoreUpdate<'a> + ?Sized
{
    fn update(&mut self, cert: Cow<LazyCert<'a>>) -> Result<()> {
        (*self).update(cert)
    }

    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        (*self).update_by(cert, merge_strategy)
    }
}

/// Merges two certificates and collects statistics.
///
/// This is primarily useful as the `merge_strategy` callback to
/// [`StoreUpdate::update_by`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MergePublicCollectStats {
    /// Number of new certificates.
    pub new: usize,

    /// Number of unchanged certificates.
    ///
    /// Note: there may be false negative.  That is some certificates
    /// may be unchanged, but the heuristic thinks that they have been
    /// updated.
    pub unchanged: usize,

    /// Number of update certificates.
    pub updated: usize,

    /// Number of errors.
    pub errors: usize,
}

impl MergePublicCollectStats {
    /// Returns a new `MergePublicCollectStats` with all stats set to 0.
    pub fn new() -> Self {
        Self {
            new: 0,
            unchanged: 0,
            updated: 0,
            errors: 0,
        }
    }
}

impl<'a: 'ra, 'ra> MergeCerts<'a, 'ra> for MergePublicCollectStats {
    /// Merges two certificates.
    ///
    /// This is primarily useful as the `merge_strategy` callback to
    /// [`StoreUpdate::update_by`].
    ///
    /// This implementation has the same merge semantics as the
    /// default implementation, but it also updates the statistics in
    /// `self`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::any::Any;
    /// use std::borrow::Cow;
    ///
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::parse::Parse;
    ///
    /// use sequoia_cert_store as cert_store;
    /// use cert_store::CertStore;
    /// use cert_store::LazyCert;
    /// use cert_store::store::MergePublicCollectStats;
    /// use cert_store::store::StoreUpdate;
    ///
    /// # fn main() -> Result<()> {
    /// let (cert, _rev) = CertBuilder::new().generate()?;
    ///
    /// let mut certs = CertStore::empty();
    ///
    /// let mut stats = MergePublicCollectStats::new();
    ///
    /// certs.update_by(Cow::Owned(LazyCert::from(cert)), &mut stats)
    ///         .expect("valid");
    ///
    /// assert_eq!(stats.new, 1);
    /// # Ok(()) }
    /// ```
    fn merge_public<'b, 'rb>(&mut self,
                             new: Cow<'ra, LazyCert<'a>>,
                             disk: Option<Cow<'rb, LazyCert<'b>>>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        let disk = if let Some(disk) = disk {
            disk
        } else {
            self.new += 1;

            if new.is_tsk() {
                return Ok(Cow::Owned(LazyCert::from(
                    new.into_owned().into_cert()?.strip_secret_key_material())))
            } else {
                return Ok(new);
            }
        };

        let fpr = new.fingerprint();

        let disk = disk.into_owned().as_cert()
            .with_context(|| {
                format!("Parsing {} as returned from the cert directory", fpr)
            })?;

        let new = new.into_owned().as_cert()
            .with_context(|| {
                format!("Parsing {} as being inserted into \
                         the cert directory",
                        fpr)
            })?;

        if disk == new {
            self.unchanged += 1;
            Ok(Cow::Owned(LazyCert::from(new)))
        } else {
            // If the on-disk version has secrets, we preserve them.
            // If new has secrets, we ignore them.
            match disk.merge_public(new) {
                Ok(merged) => {
                    self.updated += 1;
                    Ok(Cow::Owned(LazyCert::from(merged)))
                }
                Err(err) => {
                    self.errors += 1;
                    Err(err.into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store;

    // Make sure we can pass a &Box<Store> where a generic type
    // needs to implement Store.
    #[test]
    fn store_boxed() -> Result<()> {
        struct Foo<'a, B>
        where B: Store<'a>
        {
            backend: B,
            _a: std::marker::PhantomData<&'a ()>,
        }

        impl<'a, B> Foo<'a, B>
        where B: Store<'a>
        {
            fn new(backend: B) -> Self
            {
                Foo {
                    backend,
                    _a: std::marker::PhantomData,
                }
            }

            fn count(&self) -> usize {
                self.backend.certs().count()
            }
        }

        let backend = store::Certs::empty();
        let backend: Box<dyn Store> = Box::new(backend);
        let foo = Foo::new(&backend);

        // Do something (anything) with the backend.
        assert_eq!(foo.count(), 0);

        Ok(())
    }

    // Make sure we can pass a &Box<StoreUpdate> where a generic type
    // needs to implement Store.
    #[test]
    fn store_update_boxed() -> Result<()> {
        struct Foo<'a, B>
        where B: StoreUpdate<'a>
        {
            backend: B,
            _a: std::marker::PhantomData<&'a ()>,
        }

        impl<'a, B> Foo<'a, B>
        where B: StoreUpdate<'a>
        {
            fn new(backend: B) -> Self
            {
                Foo {
                    backend,
                    _a: std::marker::PhantomData,
                }
            }

            fn count(&self) -> usize {
                self.backend.certs().count()
            }
        }

        let backend = store::Certs::empty();
        let mut backend: Box<dyn StoreUpdate> = Box::new(backend);
        let foo = Foo::new(&mut backend);

        // Do something (anything) with the backend.
        assert_eq!(foo.count(), 0);

        Ok(())
    }

    #[test]
    fn is_email() {
        assert!(UserIDQueryParams::is_email("foo@domain.com").is_ok());

        // Need a local part.
        assert!(UserIDQueryParams::is_email("@domain.com").is_err());
        // Need a domain.
        assert!(UserIDQueryParams::is_email("foo@").is_err());

        // One @
        assert!(UserIDQueryParams::is_email("foo").is_err());
        assert!(UserIDQueryParams::is_email("foo@@domain.com").is_err());
        assert!(UserIDQueryParams::is_email("foo@a@domain.com").is_err());

        // Bare email address, not wrapped in angle brackets.
        assert!(UserIDQueryParams::is_email("<foo@domain.com>").is_err());

        // Whitespace is not allowed.
        assert!(UserIDQueryParams::is_email(" foo@domain.com").is_err());
        assert!(UserIDQueryParams::is_email("foo o@domain.com").is_err());
        assert!(UserIDQueryParams::is_email("foo@do main.com").is_err());
        assert!(UserIDQueryParams::is_email("foo@domain.com ").is_err());
    }

    #[test]
    fn is_domain() {
        assert!(UserIDQueryParams::is_domain("domain.com").is_ok());

        // No at.
        assert!(UserIDQueryParams::is_domain("foo").is_ok());
        assert!(UserIDQueryParams::is_domain("@domain.com").is_err());
        assert!(UserIDQueryParams::is_domain("foo@").is_err());
        assert!(UserIDQueryParams::is_domain("foo@@domain.com").is_err());
        assert!(UserIDQueryParams::is_domain("foo@a@domain.com").is_err());
        assert!(UserIDQueryParams::is_domain("<foo@domain.com>").is_err());
    }

    include!("../tests/keyring.rs");

    // Check that MergePublicCollectStats works as advertised.
    #[test]
    fn store_update_merge_public_collect_stats() {
        use std::borrow::Cow;
        use std::collections::HashSet;

        use openpgp::Cert;
        use openpgp::parse::Parse;

        use crate::CertStore;
        use crate::store::MergePublicCollectStats;

        assert_eq!(keyring::certs.len(), 12);

        let mut certs = CertStore::empty();

        let mut stats = MergePublicCollectStats::new();

        let mut seen = HashSet::new();

        for (i, cert) in keyring::certs.iter().enumerate() {
            let cert = Cert::from_bytes(&cert.bytes()).expect("valid");
            let fpr = cert.fingerprint();
            seen.insert(fpr.clone());

            certs.update_by(Cow::Owned(LazyCert::from(cert)), &mut stats)
                .expect("valid");

            eprintln!("After inserting {} ({}), stats: {:?}",
                      i, fpr, stats);

            assert_eq!(stats.new, seen.len());
            assert_eq!(stats.new + stats.updated + stats.unchanged, i + 1);
        }

        let new = stats.new;
        let updated = stats.updated;
        let unchanged = stats.unchanged;

        // Insert again.  This time nothing should change.
        for (i, cert) in keyring::certs.iter().enumerate() {
            let cert = Cert::from_bytes(&cert.bytes()).expect("valid");
            let fpr = cert.fingerprint();

            certs.update_by(Cow::Owned(LazyCert::from(cert)), &mut stats)
                .expect("valid");

            eprintln!("After reinserting {} ({}), stats: {:?}",
                      i, fpr, stats);

            // These should not change:
            assert_eq!(stats.new, new);
            // Update should also not change, but there may be false
            // positives.
            assert_eq!(stats.unchanged + stats.updated,
                       updated + unchanged + i + 1);
        }
    }
}
