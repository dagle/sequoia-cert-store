use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::str;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::packet::UserID;

use crate::store::StoreError;
use crate::store::UserIDQueryParams;

use super::TRACE;

/// A helper data structure for implementations of [`Store`].
///
/// This data structure maintains an in-memory index of User IDs and
/// email addresses, and maps them to fingerprints.  It is a
/// convenient helper for a [`Store`] implementing
/// [`Store::select_userid`].
///
/// [`Store`]: crate::Store
/// [`Store::select_userid`]: crate::Store::select_userid
///
/// This data structure returns certificates with a given User ID or
/// email address in `O(log n)` time.  Substring and case insensitive
/// matching, however, currently requires `O(n)` time.
pub struct UserIDIndex {
    by_userid: BTreeMap<UserID, BTreeSet<Fingerprint>>,

    // The *normalized* email.
    //
    // XXX: As we also want to search by domain, it would be better to
    // use a different reprentation / different data structure to
    // avoid having to do a full scan.  One possibility would be to
    // use a `BTreeMap::range`.  That requires a bit of gynastics.
    // Alternatively we could use a trie, which is keyed on (domain,
    // localpart).
    by_email: BTreeMap<String, BTreeSet<Fingerprint>>,
}

impl Default for UserIDIndex {
    fn default() -> Self {
        UserIDIndex {
            by_userid: Default::default(),
            by_email: Default::default(),
        }
    }
}

impl UserIDIndex {
    /// Returns a new, empty UserIDIndex.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry to UserIDIndex.
    ///
    /// This does *not* support removing mappings from the index.
    /// That is, if this function is called with the same fingerprint,
    /// but a User ID is removed, then the User ID is not removed from
    /// the index.  Normally, this doesn't matter as User IDs are not
    /// removed (certificates are append only data structures).
    pub fn insert<I>(&mut self, fpr: &Fingerprint, userids: I)
        where I: Iterator<Item=UserID>
    {
        for userid in userids {
            self.by_userid.entry(userid.clone())
                .or_default()
                .insert(fpr.clone());

            if let Ok(Some(email)) = userid.email_normalized() {
                self.by_email.entry(email)
                    .or_default()
                    .insert(fpr.clone());
            }
        }
    }

    /// An implementation of [`Store::select_userid`].
    ///
    /// [`Store::select_userid`]: crate::Store::select_userid
    pub fn select_userid(&self, params: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Fingerprint>>
    {
        tracer!(TRACE, "UserIDIndex::select_userid");
        t!("params: {:?}, pattern: {:?}", params, pattern);

        // XXX: If you change this function,
        // UserIDQueryParams::select_userid contains similar code.
        // Update that too.
        let mut matches = match params {
            UserIDQueryParams {
                anchor_start: true,
                anchor_end: true,
                email: false,
                ignore_case: false,
            } => {
                // Exact User ID match.
                let userid = UserID::from(pattern);
                self.by_userid.get(&userid)
                    .ok_or_else(|| {
                        StoreError::NoMatches(pattern.into())
                    })?
                    .iter()
                    .cloned()
                    .collect()
            }

            UserIDQueryParams {
                anchor_start: true,
                anchor_end: true,
                email: true,
                ignore_case: false,
            } => {
                // Exact email match.
                self.by_email.get(pattern)
                    .ok_or_else(|| {
                        StoreError::NoMatches(pattern.into())
                    })?
                    .iter()
                    .cloned()
                    .collect()
            }

            UserIDQueryParams {
                anchor_start,
                anchor_end,
                email,
                ignore_case,
            } => {
                // Substring search.
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

                // Checks if user id a match.
                let check = |userid: &str| -> bool {
                    let mut userid = userid;
                    let _userid: String;
                    if *ignore_case {
                        _userid = userid.to_lowercase();
                        userid = &_userid[..];
                    }

                    t!("Considering if {:?} matches {:?} \
                        (anchors: {}, {}, ignore case: {})",
                       pattern, userid, anchor_start, anchor_end,
                       ignore_case);

                    // XXX: Consier using
                    // https://crates.io/crates/memchr instead.
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
                };

                if *email {
                    self.by_email
                        .iter()
                        .filter_map(|(email, matches)| {
                            if check(email) {
                                Some(matches.iter())
                            } else {
                                None
                            }
                        })
                        .flatten()
                        .cloned()
                        .collect::<Vec<Fingerprint>>()
                } else {
                    self.by_userid
                        .iter()
                        .filter_map(|(userid, matches)| {
                            // If it is not UTF-8 encoded.  Ignore it.
                            let userid = str::from_utf8(userid.value()).ok()?;
                            if check(userid) {
                                Some(matches.iter())
                            } else {
                                None
                            }
                        })
                        .flatten()
                        .cloned()
                        .collect::<Vec<Fingerprint>>()
                }
            }
        };

        if matches.is_empty() {
            return Err(StoreError::NoMatches(pattern.into()).into());
        }

        matches.sort();
        matches.dedup();

        Ok(matches)
    }
}
