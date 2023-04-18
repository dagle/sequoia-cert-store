use std::borrow::Cow;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;

use rusqlite::{
    CachedStatement,
    Connection,
    OpenFlags,
    OptionalExtension,
    params,
    Row,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    cert::raw::RawCertParser,
    Fingerprint,
    KeyHandle,
    KeyID,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
};

use crate::LazyCert;
use crate::Result;
use crate::Store;
use crate::StoreUpdate;
use crate::store::MergeCerts;
use crate::store::StoreError;
use crate::store::UserIDQueryParams;

// Maximum busy wait time.
pub const BUSY_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(5);

// The location of the keys DB relative to the user's home directory.
pub const KEYS_DB: &[ &str ] = &[ "keys.db" ];

const TRACE: bool = true;

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Opening the database failed: {1}")]
    InitCannotOpenDB(#[source] anyhow::Error, String),

    #[error("Unknown error: {1}")]
    UnknownError(#[source] anyhow::Error, String),

    #[error("Database error: {1}")]
    UnknownDbError(#[source] anyhow::Error, String),

    #[error("Cannot delete key: {0}")]
    CannotDeleteKey(#[source] anyhow::Error, String),
}

// Transforms an error from some error type to the pep::Error.
macro_rules! wrap_err {
    ($e:expr, $err:ident, $msg:expr) => {
        $e.map_err(|err| {
            eprintln!("Error: {}: {}", err, $msg);
            anyhow::Error::from(Error::$err(
                anyhow::Error::from(err).into(),
                String::from($msg)))
        })
    }
}

/// A pEp certificate store backend.
///
/// A backend, which provides access to a [pEp] certificate store.
///
/// [pEp]: https://gitea.pep.foundation/pEp.foundation/pEpEngine
pub struct Pep {
    conn: rusqlite::Connection,
}

// Generates a convenience method that returns a prepared statement
// for the specified sql.  If preparing the statement results in an
// error, the error is converted to out native error type.
macro_rules! sql_stmt {
    ($name:ident, $sql:expr) => {
        fn $name(conn: &Connection) -> Result<CachedStatement<'_>> {
            let mut name: &str = stringify!($name);
            if name.ends_with("_stmt") {
                name = &name[..name.len() - "_stmt".len()];
            }
            wrap_err!(
                conn.prepare_cached(
                    $sql),
                UnknownDbError,
                format!("preparing {} query", name))
        }
    }
}

// Execute a query to load certificates, and actually load the
// certificates.
macro_rules! cert_query {
    ($stmt:expr, $args:expr, $err:expr) => {{
        let rows = wrap_err!(
            $stmt.query_map($args, Self::key_load),
            UnknownDbError,
            "executing query")?;

        let mut results: Vec<_> = Vec::new();
        for row in rows {
            let (keydata, _private)
                = wrap_err!(row, UnknownError, "parsing result")?;
            match Cert::from_bytes(&keydata) {
                Ok(cert) => results.push(Cow::Owned(LazyCert::from(cert))),
                Err(err) => {
                    t!("Warning: unable to parse a certificate: {}\n{:?}",
                       err, String::from_utf8(keydata));
                }
            }
        }

        if results.is_empty() {
            Err(anyhow::Error::from($err))
        } else {
            Ok(results)
        }
    }}
}

impl Pep {
    /// Opens a `Pep` certificate store.
    ///
    /// If `path` is `None`, then this uses the default location, which
    /// is `$HOME/.pEp/keys.db`.
    ///
    /// This initializes the database, if necessary.
    pub fn open<P>(path: Option<P>) -> Result<Self>
        where P: AsRef<Path>
    {
        match path {
            Some(p) => Self::init_(Some(p.as_ref())),
            None => {
                let mut set = false;
                let mut keys_db = PathBuf::new();

                #[cfg(not(windows))]
                if cfg!(debug_assertions) {
                    if let Ok(pep_home) = std::env::var("PEP_HOME") {
                        set = true;
                        keys_db = PathBuf::from(pep_home);
                    }
                }

                if ! set {
                    if let Some(home) = dirs::home_dir() {
                        keys_db = home
                    } else {
                        return Err(anyhow::anyhow!(
                            "Failed to find home directory"));
                    }
                }

                for n in KEYS_DB {
                    keys_db.push(n);
                }

                Self::init_(Some(&keys_db))
            }
        }
    }

    /// Returns a new `Pep`.
    ///
    /// This uses an in-memory sqlite database.
    pub fn empty() -> Result<Self> {
        Self::init_in_memory()
    }

    /// Returns a new `Pep`.
    ///
    /// This uses an in-memory sqlite database, and loads it with the
    /// keyring.
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Self> {
        tracer!(TRACE, "Pep::from_bytes");

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

    /// Returns a new `Pep`.
    ///
    /// This uses an in-memory sqlite database, and loads it with the
    /// specified certificates.
    pub fn from_certs<'a, I>(certs: impl IntoIterator<Item=I>)
        -> Result<Self>
        where I: Into<LazyCert<'a>>
    {
        let mut r = Self::init_in_memory()?;
        for cert in certs {
            r.update(Cow::Owned(cert.into())).expect("implementation doesn't fail")
        }

        Ok(r)
    }

    /// Initializes an in-memory key store.
    ///
    /// This is used for the unit tests.
    //#[cfg(test)]
    pub(crate) fn init_in_memory() -> Result<Self> {
        Self::init_(None)
    }

    fn init_(home: Option<&Path>) -> Result<Self> {
        let mut keys_db = PathBuf::new();

        let conn = if let Some(home) = home {
            keys_db.push(home);

            if home.is_dir() {
                for n in KEYS_DB {
                    keys_db.push(n);
                }
            }

            wrap_err!(
                Connection::open_with_flags(
                    &keys_db,
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                        | OpenFlags::SQLITE_OPEN_CREATE
                        | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE),
                InitCannotOpenDB,
                format!("Opening keys DB ('{}')", keys_db.display()))?
        } else {
            // Create an in-memory DB.
            wrap_err!(
                Connection::open_in_memory(),
                InitCannotOpenDB,
                "Creating in-memory keys DB")?
        };

        wrap_err!(
            conn.execute_batch("PRAGMA secure_delete=true;
                                PRAGMA foreign_keys=true;
                                PRAGMA locking_mode=NORMAL;
                                PRAGMA journal_mode=WAL;"),
            InitCannotOpenDB,
            format!("Setting pragmas on keys DB ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.busy_timeout(BUSY_WAIT_TIME),
            InitCannotOpenDB,
            format!("Setting busy time ('{}')", keys_db.display()))?;

        wrap_err!(
            conn.create_collation("EMAIL", Self::email_cmp),
            InitCannotOpenDB,
            format!("Registering EMAIL collation function"))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS keys (
                    primary_key TEXT UNIQUE PRIMARY KEY,
                    secret BOOLEAN,
                    tpk BLOB
                 );
                 CREATE INDEX IF NOT EXISTS keys_index
                   ON keys (primary_key, secret)"),
            InitCannotOpenDB,
            format!("Creating keys table ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS subkeys (
                   subkey TEXT NOT NULL /* KeyID */,
                   primary_key TEXT NOT NULL /* Fingerprint */,
                   UNIQUE(subkey, primary_key),
                   FOREIGN KEY (primary_key)
                       REFERENCES keys(primary_key)
                     ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS subkeys_index
                   ON subkeys (subkey, primary_key)"),
            InitCannotOpenDB,
            format!("Creating subkeys table ('{}')",
                    keys_db.display()))?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS userids (
                    userid TEXT NOT NULL COLLATE EMAIL,
                    primary_key TEXT NOT NULL,
                    UNIQUE(userid, primary_key),
                    FOREIGN KEY (primary_key)
                        REFERENCES keys(primary_key)
                      ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS userids_index
                   ON userids (userid COLLATE EMAIL, primary_key)"),
            InitCannotOpenDB,
            format!("Creating userids table ('{}')",
                    keys_db.display()))?;

        Ok(Pep {
            conn,
        })
    }

    // Returns a prepared statement for finding a certificate by
    // primary key fingerprint.
    sql_stmt!(cert_find_stmt,
              "SELECT tpk, secret FROM keys WHERE primary_key == ?");

    // This only works for v4 certificates!  For v6 certificates the
    // keyid is the start of the fingerprint, not the end.
    sql_stmt!(cert_find_by_keyid_stmt,
              "SELECT tpk, secret FROM keys WHERE primary_key like '%' || ?");

    // Returns a prepared statement for finding a key by primary key
    // fingerprint.
    sql_stmt!(tsk_find_stmt,
              "SELECT tpk, secret FROM keys
                 WHERE primary_key == ? and secret == 1");

    // Returns a prepared statement for finding a certificate that
    // contains a key with the specified key id.  That is, this
    // matches on the primary key's key ID as well as any subkeys' key
    // ID.
    sql_stmt!(cert_find_with_key_stmt,
              "SELECT tpk, secret FROM subkeys
                LEFT JOIN keys
                 ON subkeys.primary_key == keys.primary_key
                WHERE subkey == ?");

    // Returns a prepared statement for finding a certificate with
    // secret key material that contains a key (with or without secret
    // key material) with the specified key id.  That is, this matches
    // on the primary key's key ID as well as any subkeys' key ID.
    sql_stmt!(tsk_find_with_key_stmt,
              "SELECT tpk, secret FROM subkeys
                LEFT JOIN keys
                 ON subkeys.primary_key == keys.primary_key
                WHERE subkey == ? and keys.secret == 1");

    // Returns a prepared statement for finding a certificate with the
    // specified email address.
    sql_stmt!(cert_find_by_email_stmt,
              "SELECT tpk, secret FROM userids
                LEFT JOIN keys
                 ON userids.primary_key == keys.primary_key
                WHERE userid == ?");

    // Returns a prepared statement for returning all the fingerprints
    // of all certificates in the database.
    sql_stmt!(cert_list_stmt,
              "select primary_key from keys");

    // Returns a prepared statement for returning all certificates in
    // the database.
    sql_stmt!(cert_all_stmt,
              "select tpk, secret from keys");

    // Returns a prepared statement for returning all certificates in
    // the database, which contain secret key material.
    sql_stmt!(tsk_all_stmt,
              "select tpk, secret from keys where secret = 1");

    // Returns a prepared statement for updating the keys table.
    sql_stmt!(cert_save_insert_primary_stmt,
              "INSERT OR REPLACE INTO keys (primary_key, secret, tpk)
                VALUES (?, ?, ?)");

    // Returns a prepared statement for updating the subkeys table.
    sql_stmt!(cert_save_insert_subkeys_stmt,
              "INSERT OR REPLACE INTO subkeys (subkey, primary_key)
                VALUES (?, ?)");

    // Returns a prepared statement for updating the userids table.
    sql_stmt!(cert_save_insert_userids_stmt,
              "INSERT OR REPLACE INTO userids (userid, primary_key)
                VALUES (?, ?)");

    // Returns a prepared statement for deleting a certificate.
    //
    // Note: due to the use of foreign keys, when a key is removed
    // from the keys table, the subkeys and userids tables are also
    // automatically update.
    sql_stmt!(cert_delete_stmt,
              "DELETE FROM keys WHERE primary_key = ?");

    // Compares two User IDs.
    //
    // Extracts the email address or URI stored in each User ID and
    // compares them.  A User ID that does not contain an email
    // address or URI is sorted earlier than one that does.
    //
    // This is used as the collation function.
    pub fn email_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        let a_userid = UserID::from(a);
        let b_userid = UserID::from(b);

        let a_email = a_userid
            .email_normalized()
            .or_else(|_| a_userid.uri())
            .ok();
        let b_email = b_userid
            .email_normalized()
            .or_else(|_| b_userid.uri())
            .ok();

        match (a_email, b_email) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(&b)
        }
    }

    // The callback used by functions returning a certificate and
    // whether the certificate contains any secret key material.
    fn key_load(row: &Row) -> rusqlite::Result<(Vec<u8>, bool)> {
        let cert = row.get(0)?;
        let secret_key_material = row.get(1)?;
        Ok((cert, secret_key_material))
    }

    /// Returns the matching TSK.
    ///
    /// Like [`Store::lookup_by_cert_fpr`], but only returns
    /// certificates with private key material.
    pub fn tsk_lookup_by_cert_fpr(&self, fpr: &Fingerprint)
        -> Result<Cow<LazyCert>>
    {
        tracer!(TRACE, "Pep::tsk_lookup_by_cert_fpr");

        let mut stmt = Self::tsk_find_stmt(&self.conn)?;

        let r = cert_query!(stmt, [ fpr.to_hex() ],
                            StoreError::NotFound(KeyHandle::from(fpr)))?;
        let r = r.into_iter()
            .next()
            .ok_or_else(|| StoreError::NotFound(KeyHandle::from(fpr)))?;
        Ok(r)
    }

    /// Returns the matching TSK.
    ///
    /// Like [`Store::lookup_by_key`], but only returns certificates
    /// with private key material.
    pub fn tsk_lookup_by_key(&self, kh: &KeyHandle)
        -> Result<Vec<Cow<LazyCert>>>
    {
        tracer!(TRACE, "Pep::tsk_lookup_by_key");

        let mut stmt = Self::tsk_find_with_key_stmt(&self.conn)?;

        let keyid = KeyID::from(kh).to_hex();
        t!("({})", keyid);

        cert_query!(stmt, [ keyid ], StoreError::NotFound(kh.clone()))
    }

    /// Returns all of the TSKs.
    ///
    /// Like [`Store::certs`], but only returns certificates with
    /// private key material.
    pub fn tsks<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert>> + 'b>
    {
        tracer!(TRACE, "Pep::tsks");

        let inner = || -> Result<Vec<_>> {
            let mut stmt = Self::tsk_all_stmt(&self.conn)?;
            cert_query!(stmt, [ ], StoreError::NoMatches("EOF".into()))
        };

        match inner() {
            Ok(results) => Box::new(results.into_iter()),
            Err(err) => {
                t!("Listing TSKs: {}", err);
                Box::new(std::iter::empty())
            }
        }
    }

    /// Deletes the specified certificate from the database.
    ///
    /// If the certificate contains any private key material, this is
    /// also deleted.
    ///
    /// Returns an error if the specified certificate is not found.
    pub fn cert_delete(&mut self, fpr: Fingerprint) -> Result<()> {
        let changes = wrap_err!(
            Self::cert_delete_stmt(&self.conn)?
                .execute(params![ fpr.to_hex() ]),
            CannotDeleteKey,
            format!("Deleting {}", fpr))?;

        if changes == 0 {
            Err(StoreError::NotFound(KeyHandle::from(fpr.clone())).into())
        } else {
            Ok(())
        }
    }
}

impl<'a> Store<'a> for Pep {
    /// Returns the certificates whose fingerprint matches the handle.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Pep::lookup_by_cert");

        let mut stmt = match kh {
            KeyHandle::Fingerprint(_) => {
                Self::cert_find_stmt(&self.conn)?
            }
            KeyHandle::KeyID(_) => {
                Self::cert_find_by_keyid_stmt(&self.conn)?
            }
        };

        cert_query!(stmt, [ kh.to_hex() ], StoreError::NotFound(kh.clone()))
    }

    /// Returns certificates that have a key with the specified
    /// handle, if any.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is not found.
    ///
    /// Note: even if you pass a fingerprint, this may return multiple
    /// certificates as the same subkey may be attached to multiple
    /// certificates.
    fn lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Pep::lookup_by_key");

        let mut stmt = Self::cert_find_with_key_stmt(&self.conn)?;

        let keyid = KeyID::from(kh).to_hex();
        t!("({})", keyid);

        let mut certs: Vec<Cow<LazyCert<'a>>>
            = cert_query!(stmt, [ keyid ], StoreError::NotFound(kh.clone()))?;

        if let KeyHandle::Fingerprint(fpr) = kh {
            // Self::cert_find_with_key_stmt works with key ids.  Make
            // sure the fingerprint appears.
            certs = certs
                .into_iter()
                .filter(|cert: &Cow<LazyCert<'a>>| -> bool {
                    cert.keys().any(|ka| &ka.fingerprint() == fpr)
                })
                .collect::<Vec<Cow<LazyCert<'a>>>>();
        }

        Ok(certs)
    }

    /// Returns certificates that have a User ID matching the
    /// specified pattern according to the query parameters.
    fn select_userid(&self, query: &UserIDQueryParams, pattern: &str)
        -> Result<Vec<Cow<LazyCert<'a>>>>
    {
        tracer!(TRACE, "Pep::select_userid");

        let results: Vec<Cow<LazyCert>>;

        match (query.email(), query.ignore_case(),
               query.anchor_start(), query.anchor_end())
        {
            // Email.
            (true, _, true, true) => {
                match UserIDQueryParams::is_email(pattern) {
                    Ok(email) => return self.lookup_by_email(&email),
                    Err(err) => {
                        t!("{:?} is not a valid email address: {}",
                           pattern, err);
                        return Ok(vec![ ]);
                    }
                }
            }

            _ => {
                // Iterate over all the certificates, and return those
                // that match.
                //
                // This is potentially very expensive.  Where possible
                // we should use the the indices to reduce false
                // positives.

                results = self.certs()
                    .filter(|cert| {
                        query.check_lazy_cert(&cert, pattern)
                    })
                    .collect();
            }
        }

        if results.is_empty() {
            Err(StoreError::NoMatches(pattern.into()).into())
        } else {
            Ok(results)
        }
    }

    /// Returns certificates that have a User ID with the specified
    /// email address.
    ///
    /// The pattern is interpreted as an email address.  It is first
    /// normalized, and then matched against the normalized email
    /// address, it is anchored, and the match is case sensitive.
    fn lookup_by_email(&self, email: &str) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Pep::lookup_by_email");

        let userid = crate::email_to_userid(&email)?;
        let email = userid.email_normalized()?.expect("have one");

        let mut stmt = Self::cert_find_by_email_stmt(&self.conn)?;

        cert_query!(stmt, [ &email ], StoreError::NoMatches(email.into()))
    }

    /// Lists all of the certificates.
    ///
    /// If a backend is not able to enumerate all the certificates,
    /// then it should return those that it knows about.  For
    /// instance, some keyservers allow certificates to be looked up
    /// by fingerprint, but not to enumerate all of the certificates.
    /// Thus, a user must not assume that if a certificate is not
    /// returned by this function, it cannot be found by name.
    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item=Fingerprint> + 'b> {
        tracer!(TRACE, "Pep::fingerprints");

        let inner = || -> Result<Vec<Fingerprint>> {
            let mut stmt = Self::cert_list_stmt(&self.conn)?;

            let rows = wrap_err!(
                stmt.query_map([ ], |row: &Row| {
                    let fpr: String = row.get(0)?;
                    Ok(fpr)
                }),
                UnknownDbError,
                "executing query")?;

            let mut results: Vec<_> = Vec::new();
            for row in rows {
                let fpr = wrap_err!(row, UnknownError, "parsing result")?;
                match fpr.parse::<Fingerprint>() {
                    Ok(fpr) => results.push(fpr),
                    Err(err) => {
                        t!("Warning: unable to parse {:?} as a fingerprint: {}",
                           fpr, err);
                    }
                }
            };

            Ok(results)
        };

        match inner() {
            Ok(results) => Box::new(results.into_iter()),
            Err(err) => {
                t!("Listing fingerprints: {}", err);
                Box::new(std::iter::empty())
            }
        }
    }

    /// Returns all of the certificates.
    ///
    /// The default implementation is implemented in terms of
    /// [`Store::fingerprints`] and [`Store::lookup_by_cert_fpr`].  Many backends
    /// will be able to do this more efficiently.
    fn certs<'b>(&'b self)
        -> Box<dyn Iterator<Item=Cow<'b, LazyCert<'a>>> + 'b>
        where 'a: 'b
    {
        tracer!(TRACE, "Pep::certs");

        let inner = || -> Result<Vec<_>> {
            let mut stmt = Self::cert_all_stmt(&self.conn)?;
            cert_query!(stmt, [ ], StoreError::NoMatches("EOF".into()))
        };

        match inner() {
            Ok(results) => Box::new(results.into_iter()),
            Err(err) => {
                t!("Error: {}", err);
                Box::new(std::iter::empty())
            }
        }
    }
}

impl<'a> StoreUpdate<'a> for Pep {
    fn update_by<'ra>(&'ra mut self, cert: Cow<'ra, LazyCert<'a>>,
                      merge_strategy: &mut dyn MergeCerts<'a, 'ra>)
        -> Result<Cow<'ra, LazyCert<'a>>>
    {
        tracer!(TRACE, "Pep::update_by");

        let fpr = cert.fingerprint();
        t!("Updating {}", fpr);

        let tx = wrap_err!(
            self.conn.transaction(),
            UnknownDbError,
            "starting transaction"
        )?;

        // If the certificate already exists, we merge the existing
        // variant with the new variant.
        let r = wrap_err!(
            Self::cert_find_stmt(&tx)?
                .query_row(&[ &fpr.to_hex() ], Self::key_load).optional(),
            UnknownDbError,
            "executing query")?;

        let existing = if let Some((existing_keydata, _)) = r {
            t!("Got {} bytes of existing certificate data",
               existing_keydata.len());
            match Cert::from_bytes(&existing_keydata) {
                Ok(existing) =>
                    Some((existing_keydata, LazyCert::from(existing))),
                Err(err) => {
                    t!("Failed to parse existing data for {} (overwriting): {}",
                       fpr, err);
                    None
                }
            }
        } else {
            t!("New certificate");
            None
        };

        let merged = if let Some((_, existing_cert)) = &existing {
            t!("Updating {}", fpr);

            merge_strategy.merge_public(cert, Some(Cow::Borrowed(existing_cert)))
                .with_context(|| {
                    format!("Merging two versions of {}", fpr)
                })?
        } else {
            t!("Inserting {}", fpr);

            merge_strategy.merge_public(cert, None)?
        };

        let merged = merged.into_owned().into_cert()
            .context("Resolving merged certificate")?;

        let mut merged_keydata = Vec::new();
        wrap_err!(
            merged.as_tsk().serialize(&mut merged_keydata),
            UnknownDbError,
            "Serializing certificate")?;

        let new_or_changed = if let Some((existing_keydata, _)) = &existing {
            &merged_keydata != existing_keydata
        } else {
            true
        };

        if ! new_or_changed {
            t!("Data unchanged.");
            return Ok(Cow::Owned(LazyCert::from(merged)));
        }

        t!("Serializing {} bytes ({:X})",
           merged_keydata.len(),
           {
               use std::collections::hash_map::DefaultHasher;
               use std::hash::Hasher;

               let mut hasher = DefaultHasher::new();

               hasher.write(&merged_keydata);
               hasher.finish()
           });

        // Save the certificate.
        {
            let mut stmt = Self::cert_save_insert_primary_stmt(&tx)?;
            wrap_err!(
                stmt.execute(
                    params![fpr.to_hex(), merged.is_tsk(), &merged_keydata]),
                UnknownDbError,
                "Executing cert_save_insert_primary")?;
        }

        // Update the subkey table.
        {
            let mut stmt = Self::cert_save_insert_subkeys_stmt(&tx)?;
            for (i, ka) in merged.keys().enumerate() {
                t!("  {}key: {} ({} secret key material)",
                   if i == 0 { "primary " } else { "sub" },
                   ka.keyid(),
                   if ka.has_secret() { "has" } else { "no" });
                wrap_err!(
                    stmt.execute(
                        params![ka.keyid().to_hex(), fpr.to_hex()]),
                    UnknownDbError,
                    "Executing cert save insert subkeys")?;
            }
        }

        // Update the userid table.
        {
            let mut stmt = Self::cert_save_insert_userids_stmt(&tx)?;

            for ua in merged.userids() {
                let uid = if let Ok(Some(email)) = ua.email_normalized() {
                    email
                } else if let Ok(Some(uri)) = ua.uri() {
                    uri
                } else {
                    continue;
                };
                t!("  User ID: {}", uid);

                wrap_err!(
                    stmt.execute(params![uid, fpr.to_hex()]),
                    UnknownDbError,
                    "Executing cert save insert userids")?;
            }
        }

        wrap_err!(
            tx.commit(),
            UnknownDbError,
            "committing transaction"
        )?;

        t!("saved");

        Ok(Cow::Owned(LazyCert::from(merged)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_db() -> Result<()> {
        tracer!(TRACE, "keys_db");

        struct Record {
            fingerprint: &'static str,
            subkeys: &'static [&'static str],
            userids: &'static [&'static str],
        }
        impl Record {
            fn fingerprint(&self) -> Fingerprint {
                self.fingerprint.parse::<Fingerprint>().expect("valid")
            }

            fn keys(&self) -> impl Iterator<Item=Fingerprint> {
                std::iter::once(self.fingerprint())
                    .chain(self.subkeys.iter().map(|sk| {
                        sk.parse::<Fingerprint>().expect("valid")
                    }))
            }
        }

        let records = &[
            Record {
                fingerprint: "04880CB55875B6548C25C729A00E4CD660454746",
                subkeys: &[
                    "F9CBBC92F2C34E518722CA77CADEEF67FAADD951",
                    "05793483F1826E44A2B866E0A7CB62B3422503EE",
                    "2C0E08F26EE06409C4712149DAC435B561D44E7B",
                ],
                userids: &[
                    "francis@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "08C6A9408241E6ED99A0A2767A6B35253722954D",
                subkeys: &[
                    "2F7B12FD253CF4ECC9255D7053D8C1B7F801D54D",
                    "DB806800E939D5F0611BCD0DD9D4C006F09088D1",
                    "9F62CE8B0786820B933427A50AC73BFE55E17D22",
                ],
                userids: &[
                    "Luca Saiu (free software hacker at pEp foundation) <positron@pep.foundation>",
                    "Luca Saiu (free software hacker, GNU maintainer, computer scientist) <iut@ageinghacker.net>",
                    "Luca Saiu (free software hacker, GNU maintainer, computer scientist) <luca.saiu@univ-paris13.fr>",
                    "Luca Saiu (free software hacker, GNU maintainer, computer scientist) <luca@ageinghacker.net>",
                    "Luca Saiu (free software hacker, GNU maintainer, computer scientist) <positron@gnu.org>",
                    "Luca Saiu (free software hacker, GNU maintainer, computer scientist) <saiu@univ-paris13.fr>",
                    "Luca Saiu <luca@saiu.ch>",
                    "Luca Saiu on mobile (do not use: only for myself) <luca-mobile@ageinghacker.net>",
                ]
            },
            Record {
                fingerprint: "10E37AA3BBFD3348CF9AE3698EF85F1B1E37396F",
                subkeys: &[
                    "E111DA754DD6839738F83CDC4A869829AAB70CBE",
                    "E3AB3FFE39F7B12880B1A7035A826CAA7026DB6F",
                ],
                userids: &[
                    "pEpUserThree <pep3@ageinghacker.net>",
                ]
            },
            Record {
                fingerprint: "1CF1202EC58B5514EADC477AAA9CAC9C7B935A45",
                subkeys: &[
                    "423D41EF768D8D1C56CAB1FD994931632B55CF76",
                    "D9947827069496C55E92D514DA2E401BDCC26140",
                    "0706AEDD2CA382D2F3B0EF5C34450D8FA47BE578",
                ],
                userids: &[
                    "john@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "22A589136F68CC46076FFA6071B2EDA40DC29CC7",
                subkeys: &[
                    "C5D71768F5D7CC5C94659384ADF2379966C74972",
                    "528A548BD73B7035AF469F3147D04DC2B74725E1",
                    "65444DDC1BB08DE9AAB7A6BA38E7A3645666C769",
                ],
                userids: &[
                    "david@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "2349DF0D7DBD60C6C20453350553D1E9E9AE5C54",
                subkeys: &[
                    "1B8185A37003F109AE7D56921908736247B42C7C",
                    "1815AFE0BEB4EE7195B8A8402F8A666BE91A400F",
                    "C55EE7CACBBCEB75228CDCFBCDFBE06BBC5F6D29",
                ],
                userids: &[
                    "sabrina@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "2533E4E13EC84A784DE6F2962C3E64162620C978",
                subkeys: &[
                    "5B71667A87F2006D8C874F448134877075548DB7",
                    "1DB026D73D7B6BB8B17646B17AB77AECC3703ED5",
                    "434E3BB9D702FF0E4B4033454D2476E6EDCA3BE2",
                ],
                userids: &[
                    "zachary@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "2F8EB6F51987B06706ED6E45064ABE0B9108844E",
                subkeys: &[
                    "3872E86087B7C38EE469BD962DD7EC6B89966D7D",
                    "AC677AC99D84F60E71BB1A533BDE948165BE1800",
                    "39C6CDBC2D0DF90960BD7FBF3AD07BB3F42BD08E",
                ],
                userids: &[
                    "gilbert@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "43C5C721DCFF1D7D8FD1372F49B0B5F169F745F3",
                subkeys: &[
                    "86801702F48ED113958C70FD28967B47191899F8",
                    "932B684FB0672F374626F8889F5599183124F72D",
                    "DD8B64AEE46E8DE72DBFBC03185B7A6512A48391",
                ],
                userids: &[
                    "ernest@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "4925E278E468D55BA68B3AC49E1F03BA787E31EA",
                subkeys: &[
                    "6C4B1AE1D50683DBF1224F0338CBCE44873FE1A7",
                    "E350B80A80C6C77E4D8D0C62C96ADEF6A2CCFA98",
                    "9578E63C4EBCB861521BE6F71949FBA7A090B71D",
                ],
                userids: &[
                    "yoko@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "4FDC731D26FAB6E8EAE6993C637DE61020C5DD1B",
                subkeys: &[
                    "BEED00902BCD166C0F2B10C51981CA07B08A2AA3",
                    "1EDB7F72E67CA292FE1F3428650BEEAE8BE0BA78",
                    "4658FDA3D8FB8E9154D2EAAFE8F03F5A4682799E",
                ],
                userids: &[
                    "bob@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "507212E4796EFBF4FF8E4B1BF411A72A5C89092C",
                subkeys: &[
                    "282E7BE3396051799239B462A9173FFEBD40DA28",
                    "DFBC57AAC0D7C9D5E5B974ADE6F0D74501D65927",
                ],
                userids: &[
                    "pEpUserTwo <pep2@ageinghacker.net>",
                ]
            },
            Record {
                fingerprint: "5C55764028BE2DD718F9DAAAD8D14CE515A32801",
                subkeys: &[
                    "71BB66F7E592075A11F97E2BB058180EE35C8BE0",
                    "D87E291B879F72682D7FA06804EEFDB17B04F78B",
                    "155A466B86DDC61DDF25E85D50B9CB75C2151872",
                ],
                userids: &[
                    "ophelia@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "68A4E57878501CF89B9844039B3560C27904221F",
                subkeys: &[
                    "C3770108DC6DC449323718F101076D890F515D6F",
                    "B99A6A6BAB7CE86DE08AFC770509657A6BAC730C",
                    "689D45E46A723E234DDC7AFAB4E5A2B2EF97E405",
                ],
                userids: &[
                    "nkls@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "6C36B5E1ED2B4B1D06CD03FF5D5025F89BBA7A07",
                subkeys: &[
                    "FFF6F17D7807A8E40F08253B1B23CEF521884A3F",
                    "0430CE889630E018D824177C1DB2D0B226A87A27",
                    "82C2CD0877B7DA063BD09ECE69AF5A6299EC8A60",
                ],
                userids: &[
                    "ziggy@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "7A757276DFF48471EA032D2B98611755153523E6",
                subkeys: &[
                    "B6F72694DFE3ED77F6E3EE6DEEE9E2E4D0403BA2",
                    "36469B4676CEE3B28710D6441C23477C835E5CEB",
                    "EE98545F41E1AFDB67C4498D42916177BEAA8874",
                ],
                userids: &[
                    "yves@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "7D8A6D4E9F5804C3F161D2FC4A4DF6C29EDD1F76",
                subkeys: &[
                    "C8016468CCDF2C33997019647F6B5258C086DC6B",
                    "19529BB44C4AE0FB5F7976194B8313F3BF069E6A",
                    "9DF6E3803A0F57579C5399962C7C1FA3369E4A4D",
                ],
                userids: &[
                    "paul@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "8049F106768CD5D6374645F3B0C0ABEFB3892D73",
                subkeys: &[
                    "69FE5FFBF2EC257B452E880066CC46F715A66DBC",
                    "C21839A49A47E534731137549079AA6B02A61A8B",
                    "D2DC92A6E0DC69F80B355308FD289E27C690EE4E",
                ],
                userids: &[
                    "mary@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "8A0293871D97E954B8397DFD072889CB0E82D77B",
                subkeys: &[
                    "614F9A11152D7D2373A4F505D49FD2CB8EEF9103",
                    "8E7242E2C05D1FB2B49CC19A6C9FF639C2D20ED2",
                    "CC68938EB2949794B5D34061132E928709CB1956",
                ],
                userids: &[
                    "randy@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "912E63F55388D9886151101CDA4FE8ECD8365D6E",
                subkeys: &[
                    "AB22733035AA5F96C357D0D3773082B0012A791A",
                    "673D7C2892CB4D38CDB1DD41AF26C6724E7E40F3",
                    "E5772DCDB9CBD8631A2A03A93F0586841937BDFE",
                ],
                userids: &[
                    "ned@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "9BC60CF498E584E5620014340C099ECDA62431FE",
                subkeys: &[
                    "6675F0E49F87BBB75D0EE762884DFEDE8DF8A5B1",
                    "C4669EDC5091DE34BEDD65331743133E219C1EB1",
                    "6F2087132F126BCFB19B8B0F94D1A2CC4A978727",
                ],
                userids: &[
                    "victor@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "9C1CCC07B3BF48BEA0278E93DC5BFE32065BD8C1",
                subkeys: &[
                    "32FF5498B9FF8E14D8575139DE99B5AACE801044",
                    "568042CD692658C0FCD8B983AC9255C490B72219",
                    "634B9C334069B2A083D1C9E66286EF138550E5C0",
                ],
                userids: &[
                    "irene@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "A20EF4E353FF61FF6B8B401AC48BF850A5E9C611",
                subkeys: &[
                    "436A273DC129DD70B4C8233B33DB91F8AAECA2FD",
                    "BA455203A9BDEC6B168EEDE851074EA7D24AA490",
                    "F1657C4DC11A61C47DF1CD628451B62D9873AE16",
                ],
                userids: &[
                    "henry@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "A2439F4C712EA9FA6B65BC17DECD473509E96847",
                subkeys: &[
                    "F691FDB3FE8683AC485CABEDAA761009D6D131A0",
                    "36ECEAE6F6A2ED1264001B98B974664B34752AFC",
                    "A762875E701B76729547C5C55609A4F9A4344957",
                ],
                userids: &[
                    "ulysses@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "AAB978A882B9A6E793960B071ADFC82AC3586C14",
                subkeys: &[
                    "F2A0CBDC287931D3D69988E5EDF969810BA5194C",
                ],
                userids: &[
                    "Volker Birk <bumens@dingens.org>",
                    "Volker Birk <dingens@bumens.org>",
                    "Volker Birk <vb@dingens.org>",
                    "Volker Birk <vb@pep-project.org>",
                    "Volker Birk <vb@pep.foundation>",
                    "Volker Birk <vb@pibit.ch>",
                    "Volker Birk <volker.birk@pep-project.org>",
                    "Volker Birk <volker.birk@pep.foundation>",
                ]
            },
            Record {
                fingerprint: "B5AAD4575B2988D99E3FB3EE973EE71028459E9A",
                subkeys: &[
                    "CA0BD82382BC588F51FDDE5083C69AF0F851437A",
                    "826E96AD20F30B027CD6DDD70D6DF17AFEF1FFBA",
                    "D798ABEE594EE900CDA2B0DECEFC4DCD7DD09BF9",
                ],
                userids: &[
                    "xenia@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "B828EF1F203645DCDE9C37B0D0D1AB8DA16D8D79",
                subkeys: &[
                    "823A732A9518DC79F687FFBC3D4778FC2C38084F",
                    "9B585A80E1C81CC7A2B9B7DDDF5F5C00DA897592",
                    "5FD13A0E30F49F9F50AD131ACDD45401DD0E759F",
                ],
                userids: &[
                    "alice@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "C11BCCBB3F843593B8975AFB958E85734EF0ADE0",
                subkeys: &[
                    "01389D318C1B7146464F7E0DDD26BFF997B128D0",
                    "13830079F9A096D9333683EAE572969A4BF0EAA1",
                    "FFA2C2B2685B4D258BDE8CCFC0D868F1963180D8",
                ],
                userids: &[
                    "ken@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "CB4287D637F9BC0CB38F978AEB64F54F552F0AB7",
                subkeys: &[
                    "CA30E474FBB1021F3CD7DB74C25C74A408C599D8",
                    "A8B3E97A82D39C6DE4890C4854E2200EE3627373",
                    "D533C66AE6DE8DC54C9D695564BF7EACFA7E07D3",
                ],
                userids: &[
                    "valeria@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "CDAE31CA330249BC5284C1F96033761A09D517DF",
                subkeys: &[
                    "8A8B91F58F4B20C3D79F3710054118196B963B7D",
                    "F9B079BE2882793F7C7EF867EA301A7C9A893815",
                    "6F2B8C671245EFF407259CE82C45488C98085D61",
                ],
                userids: &[
                    "wyatt@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "D27B4F82C717A04DFF3A986489929D075908994E",
                subkeys: &[
                    "C8F9A3AC57C402EACACCA0925DFAD7D10C678DBE",
                    "F405EE2559711EAC16F4B0E37903174192105E48",
                    "0878C54CDFC955756A002259A685E0D6F5530952",
                ],
                userids: &[
                    "xavier@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "E1C12525BFAF4F092D109F2152B7186506DCC483",
                subkeys: &[
                    "F03D87EDA63C5BFAB30182CC2B45B386DCB3A0CF",
                    "8AF21DCC9537E2644C844383DB24D05A4CFF4204",
                    "84FE32BC7C903DE726A36E18BDE25B8E80237EE2",
                ],
                userids: &[
                    "tamara@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "E4C1FB98268170769154C21BBD1637EEB34E933B",
                subkeys: &[
                    "60EF08693793CBC2A0452C59E7D3FED35EAF68B9",
                    "ECA3B609C1661937540C50871D7FA83415FD0C9C",
                    "DB2234A696DBAF7CDF04264FB929651D1EDAD644",
                ],
                userids: &[
                    "zenobia@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "EB4750A0B0A0F558ED5F768F8B893A26133B3F66",
                subkeys: &[
                    "6D600191F05865CFE5F4B93214180E23218FFEDA",
                    "C101BCA52FBC77A2F00241B58F07A6D986845B5A",
                    "A35FC3F687EDE1749A677486F300560992B840A8",
                ],
                userids: &[
                    "owen@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "F29B751A3123A1502E5C0665745FB6564FC5F7DC",
                subkeys: &[
                    "A1CEFF2AD2055D84311A34DD19BAAA837AA0EDE3",
                    "B3358A65A142E96D742006A189E01368B3CFEA66",
                    "ADE383408E6A66E64934114FDF466C19D1E09129",
                ],
                userids: &[
                    "carol@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "F749E746EAAFEB7A634BCE8A4C34BA7BC16F86B3",
                subkeys: &[
                    "59901649426B2C70871133CB0DCD1F051766107F",
                    "4560CBD01CD2BE321EC50DF9C1B27AC998ABABB8",
                    "83E8BC30EE962BF2D160A3F59C4396FA8EE7BB36",
                ],
                userids: &[
                    "quasimodo@fake.pep.foundation",
                ]
            },
            Record {
                fingerprint: "FBD19974E304C95589F976BD71059020F2CC257C",
                subkeys: &[
                    "90FE526A624C3F4503B8E77E94E766EE6359246D",
                    "32294836077FF576868D4958848F73B0CCB468D9",
                    "104807CB7B51CD3CD2FF7366780F3DCE8BA84184",
                ],
                userids: &[
                    "louis@fake.pep.foundation",
                ]
            }
        ];


        let tmp = tempfile::tempdir()?;

        let filename = tmp.path().join("keys.db");
        {
            let mut orig = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            orig.push("tests/pep/keys.db");

            let data = std::fs::read(orig)?;
            std::fs::write(&filename, data)?;
        }

        let mut pep = Pep::open(Some(filename)).expect("can open");

        // Certs.
        assert_eq!(records.len(), pep.certs().count());

        // Fingerprints.
        {
            let mut pep_fprs = pep.fingerprints().collect::<Vec<Fingerprint>>();
            pep_fprs.sort();

            let mut expected_fprs = records.iter()
                .map(|r| r.fingerprint())
                .collect::<Vec<Fingerprint>>();
            expected_fprs.sort();

            assert_eq!(pep_fprs.len(), expected_fprs.len());
            assert_eq!(pep_fprs, expected_fprs);
        }

        for record in records.iter() {
            // Lookup by certs fingerprint.
            for (i, key) in record.keys().enumerate() {
                let r = pep.lookup_by_cert_fpr(&key);
                if i == 0 {
                    assert!(r.is_ok());
                } else {
                    // Looking up by subkey won't work.
                    assert!(r.is_err());
                }

                // By fingerprint.
                let kh = KeyHandle::from(key);
                let r = pep.lookup_by_cert(&kh).ok().map(|c| c.len());
                if i == 0 {
                    assert_eq!(r, Some(1));
                } else {
                    assert_eq!(r, None);
                }

                // By Key ID.
                let kh = KeyHandle::from(KeyID::from(kh));
                let r = pep.lookup_by_cert(&kh).ok().map(|c| c.len());
                if i == 0 {
                    assert_eq!(r, Some(1));
                } else {
                    assert_eq!(r, None);
                }
            }

            // Lookup by keys.
            for key in record.keys() {
                // By fingerprint.
                let kh = KeyHandle::from(key);
                assert_eq!(pep.lookup_by_key(&kh).ok().map(|c| c.len()),
                           Some(1));

                // By Key ID.
                let kh = KeyHandle::from(KeyID::from(kh));
                assert_eq!(pep.lookup_by_key(&kh).ok().map(|c| c.len()),
                           Some(1));
            }

            // Look up User IDs.
            for &userid in record.userids.into_iter() {
                t!("Checking that {} has User ID {:?}",
                   record.fingerprint(), userid);
                let matches = pep.lookup_by_userid(&UserID::from(userid))
                    .unwrap_or(Vec::new())
                    .into_iter()
                    .map(|c| c.fingerprint())
                    .collect::<Vec<Fingerprint>>();
                assert_eq!(matches, vec![ record.fingerprint() ]);

                if let Ok(email) = UserIDQueryParams::is_email(userid) {
                    t!("Checking that {} has email {:?}",
                       record.fingerprint(), email);

                    let matches = pep.lookup_by_email(&email)
                        .unwrap_or(Vec::new())
                        .into_iter()
                        .map(|c| c.fingerprint())
                        .collect::<Vec<Fingerprint>>();
                    assert_eq!(matches, vec![ record.fingerprint() ]);
                }
            }
        }

        // Look up by domain.
        t!("email domain");
        let matches = pep.lookup_by_email_domain("fake.pep.foundation")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 33);

        let matches = pep.lookup_by_email_domain("@fake.pep.foundation")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 0);

        let matches = pep.lookup_by_email_domain("e.pep.foundation")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 0);

        let matches = pep.lookup_by_email_domain("pep.foundation")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 2);

        let matches = pep.lookup_by_email_domain("ageinghacker.net")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 3);

        // grep
        t!("Grepping");
        let matches = pep.grep_email("pep.foundation")
            .unwrap_or(Vec::new())
            .into_iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches.len(), 35);

        t!("TSKs");
        let tsk_fpr = "EB4750A0B0A0F558ED5F768F8B893A26133B3F66"
            .parse::<Fingerprint>()
            .expect("valid");
        let tsks = records.iter()
            .filter(|c| c.fingerprint() == tsk_fpr)
            .collect::<Vec<_>>();
        assert_eq!(tsks.len(), 1);
        let tsk_record = tsks.into_iter().next().expect("have one");
        assert_eq!(tsk_record.fingerprint(), tsk_fpr);

        let tsks = pep.tsks()
            .map(|c| c.into_owned().into_cert().expect("valid"))
            .collect::<Vec<Cert>>();
        let matches = tsks
            .iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches, vec![ tsk_record.fingerprint() ]);
        let tsk = tsks.into_iter().next().expect("have one");

        t!("Updating the tsk");
        let tsk_as_cert = tsk.clone().strip_secret_key_material();
        pep.update(Cow::Owned(LazyCert::from(tsk_as_cert)))
            .expect("can update");

        t!("Checking that the TSK is still a TSK");
        let tsks = pep.tsks()
            .map(|c| c.into_owned().into_cert().expect("valid"))
            .collect::<Vec<Cert>>();
        let matches = tsks
            .iter()
            .map(|c| c.fingerprint())
            .collect::<Vec<Fingerprint>>();
        assert_eq!(matches, vec![ tsk_record.fingerprint() ]);
        let tsk_updated = tsks.into_iter().next().expect("have one");

        assert_eq!(tsk, tsk_updated);

        Ok(())
    }
}
