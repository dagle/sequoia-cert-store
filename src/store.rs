use std::borrow::Cow;
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::Cert;
use openpgp::cert::ValidCert;
use openpgp::cert::raw::RawCert;
use openpgp::packet::UserID;

mod userid_index;
pub use userid_index::UserIDIndex;

pub mod certd;
pub use certd::CertD;

pub mod certs;
pub use certs::Certs;

pub mod keyserver;
pub use keyserver::KeyServer;

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
}

/// [`Store`] specific error codes.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum StoreError {
    /// No certificate was found.
    #[error("{0} was not found")]
    NotFound(KeyHandle),

    #[error("No certificates matched {0}")]
    NoMatches(String),
}

/// Returns certificates from a backing store.
pub trait Store<'a> {
    /// Returns the certificates whose fingerprint matches the handle.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Returns the certificate with the specified fingerprint, if any.
    ///
    /// Returns [`StoreError::NotFound`] if the certificate is not found.
    ///
    /// The default implementation is implemented in terms of
    /// [`Store::by_cert`].
    fn by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        let kh = KeyHandle::from(fingerprint.clone());

        self.by_cert(&kh)
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
    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Returns certificates that have a User ID matching the
    /// specified pattern according to the query parameters.
    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>;

    /// Performs an exact match on the User ID.
    ///
    /// The pattern is anchored, and the match is case sensitive.
    fn by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
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

    /// Returns certificates that have User ID with the specified
    /// email address.
    ///
    /// The pattern is interpreted as an email address.  It is first
    /// normalized, and then matched against the normalized email
    /// address, it is anchored, and the match is case sensitive.
    fn by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
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
    fn by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
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
    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b>;

    /// Returns all of the certificates.
    ///
    /// The default implementation is implemented in terms of
    /// [`Store::list`] and [`Store::by_cert_fpr`].  Many backends
    /// will be able to do this more efficiently.
    fn iter<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        Box::new(self.list()
            .filter_map(|fpr| {
                self.by_cert_fpr(&fpr).ok()
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
    fn precompute(&self) {
    }
}

// The references in Store need a different lifetime from the contents
// of the Box.  Otherwise, a `Backend` that is a `&Box<Store>` would
// create a self referential data structure.
impl<'a: 't, 't, T> Store<'a> for Box<T>
where T: Store<'a> + ?Sized + 't
{
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().by_cert(kh)
    }

    fn by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        self.as_ref().by_cert_fpr(fingerprint)
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        self.as_ref().select_userid(query, pattern)
    }

    fn by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().grep_userid(pattern)
    }

    fn by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().grep_email(pattern)
    }

    fn by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        self.as_ref().by_email_domain(domain)
    }

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        self.as_ref().list()
    }

    fn iter<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        self.as_ref().iter()
    }

    fn precompute(&self) {
        self.as_ref().precompute()
    }
}

impl<'a: 't, 't, T> Store<'a> for &'t T
where T: Store<'a> + ?Sized
{
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).by_cert(kh)
    }

    fn by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        (*self).by_cert_fpr(fingerprint)
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        (*self).select_userid(query, pattern)
    }

    fn by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).grep_userid(pattern)
    }

    fn by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).grep_email(pattern)
    }

    fn by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (*self).by_email_domain(domain)
    }

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        (*self).list()
    }

    fn iter<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        (*self).iter()
    }

    fn precompute(&self) {
        (*self).precompute()
    }
}

impl<'a: 't, 't, T> Store<'a> for &'t mut T
where T: Store<'a> + ?Sized
{
    fn by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).by_cert(kh)
    }

    fn by_cert_fpr(&self, fingerprint: &Fingerprint)
        -> Result<Cow<LazyCert<'a>>>
    {
        (**self).by_cert_fpr(fingerprint)
    }

    fn by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).by_key(kh)
    }

    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        (**self).select_userid(query, pattern)
    }

    fn by_userid(&self, userid: &UserID) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).by_userid(userid)
    }

    fn grep_userid(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).grep_userid(pattern)
    }

    fn by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).by_email(email)
    }

    fn grep_email(&self, pattern: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).grep_email(pattern)
    }

    fn by_email_domain(&self, domain: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        (**self).by_email_domain(domain)
    }

    fn list<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        (**self).list()
    }

    fn iter<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        (**self).iter()
    }

    fn precompute(&self) {
        (**self).precompute()
    }
}
/// Provides an interface to update a backing store.
pub trait StoreUpdate<'a>: Store<'a> {
    // Insert a certificate.
    fn insert_cert(&mut self, cert: Cert) -> Result<()> {
        self.insert_lazy_cert(cert.into())
    }

    // Insert a certificate.
    fn insert_raw_cert(&mut self, cert: RawCert<'a>) -> Result<()> {
        self.insert_lazy_cert(cert.into())
    }

    // Insert a certificate.
    fn insert_lazy_cert(&mut self, cert: LazyCert<'a>) -> Result<()>;
}

impl<'a: 't, 't, T> StoreUpdate<'a> for Box<T>
where T: StoreUpdate<'a> + ?Sized + 't
{
    fn insert_cert(&mut self, cert: Cert) -> Result<()> {
        self.as_mut().insert_cert(cert)
    }

    fn insert_raw_cert(&mut self, cert: RawCert<'a>) -> Result<()> {
        self.as_mut().insert_raw_cert(cert)
    }

    fn insert_lazy_cert(&mut self, cert: LazyCert<'a>) -> Result<()> {
        self.as_mut().insert_lazy_cert(cert)
    }
}

impl<'a: 't, 't, T> StoreUpdate<'a> for &'t mut T
where T: StoreUpdate<'a> + ?Sized
{
    fn insert_cert(&mut self, cert: Cert) -> Result<()> {
        (*self).insert_cert(cert)
    }

    fn insert_raw_cert(&mut self, cert: RawCert<'a>) -> Result<()> {
        (*self).insert_raw_cert(cert)
    }

    fn insert_lazy_cert(&mut self, cert: LazyCert<'a>) -> Result<()> {
        (*self).insert_lazy_cert(cert)
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
                self.backend.iter().count()
            }
        }

        let backend = store::Certs::from_certs(std::iter::empty())?;
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
                self.backend.iter().count()
            }
        }

        let backend = store::Certs::from_certs(std::iter::empty())?;
        let mut backend: Box<dyn StoreUpdate> = Box::new(backend);
        let foo = Foo::new(&mut backend);

        // Do something (anything) with the backend.
        assert_eq!(foo.count(), 0);

        Ok(())
    }
}
