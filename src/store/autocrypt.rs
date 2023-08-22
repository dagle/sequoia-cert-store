use std::borrow::Cow;
use std::iter::Sum;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Context;

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use openpgp::cert::CertBuilder;
use openpgp::cert::CipherSuite;
use openpgp::packet::Signature;
use openpgp::types::KeyFlags;
use openpgp::policy::Policy;
use rusqlite::{params, CachedStatement, Connection, OpenFlags, OptionalExtension, Row};

use openpgp::{
    cert::raw::RawCertParser, packet::UserID, parse::Parse, serialize::Serialize, Cert,
    Fingerprint, KeyHandle, KeyID,
};
use sequoia_autocrypt::AutocryptHeader;
use sequoia_autocrypt::AutocryptHeaderType;
use sequoia_autocrypt::AutocryptSetupMessage;
use sequoia_openpgp as openpgp;

use crate::store::MergeCerts;
use crate::store::StoreError;
use crate::store::UserIDQueryParams;
use crate::LazyCert;
use crate::Result;
use crate::Store;
use crate::StoreUpdate;

// Maximum busy wait time.
pub const BUSY_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(5);

// The location of the keys DB relative to the user's home directory.
pub const KEYS_DB: &[&str] = &["_autocrypt.sqlite"];

use crate::TRACE;

#[derive(PartialEq, Debug)]
pub struct Account {
    pub mail: String,
    pub fpr: Option<Fingerprint>,

    // If we want to save settings into the database. For some applications
    // you might want configure this in your normal settings rather
    // having it in the database.
    pub prefer: Prefer,
    pub enable: bool,
}

impl Account {
    pub(crate) fn new(mail: &str, fpr: Option<Fingerprint>) -> Self {
        Account {
            mail: mail.to_owned(),
            fpr,
            prefer: Prefer::Nopreference,
            enable: false,
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum Prefer {
    Mutual,
    #[default]
    Nopreference,
}

pub struct Peer {
    pub mail: String,
    pub account: String,
    pub last_seen: DateTime<Utc>,
    pub timestamp: Option<DateTime<Utc>>,
    pub cert_fpr: Option<Fingerprint>,
    pub gossip_timestamp: Option<DateTime<Utc>>,
    pub gossip_fpr: Option<Fingerprint>,
    pub prefer: Prefer,
    pub counting_since: DateTime<Utc>,
    pub count_have_ach: u32,
    pub count_no_ach: u32,
}

impl Peer {
    pub fn new(
        mail: &str,
        account: &str,
        now: DateTime<Utc>,
        key: & Cert,
        gossip: bool,
        prefer: Prefer,
    ) -> Self {
        if !gossip {
            Peer {
                mail: mail.to_owned(),
                account: account.to_owned(),
                last_seen: now,
                timestamp: Some(now),
                cert_fpr: Some(key.fingerprint()),
                gossip_timestamp: None,
                gossip_fpr: None,
                prefer,
                counting_since: now,
                count_have_ach: 0,
                count_no_ach: 0,
            }
        } else {
            Peer {
                mail: mail.to_owned(),
                account: account.to_owned(),
                last_seen: now,
                timestamp: None,
                cert_fpr: None,
                gossip_timestamp: Some(now),
                gossip_fpr: Some(key.fingerprint()),
                prefer: Prefer::default(),
                counting_since: now,
                count_have_ach: 0,
                count_no_ach: 0,
            }
        }
    }

    // // Determine if encryption is possible
    // pub(crate) fn can_encrypt(&self, policy: &dyn Policy) -> bool {
    //     valid_cert(&self.cert, policy) || valid_cert(&self.gossip_cert, policy)
    // }
    //
    // pub(crate) fn preliminary_recommend(&self, policy: &dyn Policy) -> UIRecommendation {
    //     if !self.can_encrypt(policy) {
    //         return UIRecommendation::Disable;
    //     }
    //     if self.cert.is_some() {
    //         let stale = self.timestamp + Duration::days(35);
    //         if stale.cmp(&self.last_seen) == Ordering::Less {
    //             return UIRecommendation::Discourage;
    //         }
    //         return UIRecommendation::Available;
    //     }
    //     if self.gossip_cert.is_some() {
    //         return UIRecommendation::Discourage;
    //     }
    //     UIRecommendation::Disable
    // }
    //
    // pub(crate) fn get_recipient<D: SqlDriver>(&self, db: &D, policy: &dyn Policy) -> Result<Recipient> {
    //     encrypt_key!(db, self.cert_fpr, policy);
    //     encrypt_key!(db, self.gossip_fpr, policy);
    //     Err(anyhow::anyhow!(
    //         "Couldn't find any key for transport encryption for peer"
    //     ))
    // }
}

/// TODO:UIRecommendation should have a string

/// UIRecommendation represent whether or not we should encrypt an email.
/// Disable means that we shouldn't try to encrypt because it's likely people
/// won't be able to read it.
/// Discourage means that we have keys for all users to encrypt it but we don't
/// we are not sure they are still valid (we haven't seen them in long while,
/// we got them from gossip etc)
/// Available means all systems are go.
#[derive(Debug, PartialEq)]
pub enum UIRecommendation {
    Disable,
    Discourage,
    Available,
    Encrypt,
}

impl Sum for UIRecommendation {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        for entry in iter {
            if entry == Self::Disable {
                return Self::Disable;
            }
            if entry == Self::Discourage {
                return Self::Discourage;
            }
            if entry != Self::Encrypt {
                return Self::Available;
            }
        }
        Self::Encrypt
    }
}

impl UIRecommendation {
    pub fn encryptable(&self) -> bool {
        if *self == Self::Disable {
            return false;
        }
        true
    }
    pub fn preferable(&self) -> bool {
        if *self == Self::Disable || *self == Self::Discourage {
            return false;
        }
        true
    }
}

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

    #[error("Cannot delete account: {0}")]
    CannotDeleteAccount(#[source] anyhow::Error, String),

    #[error("Cannot delete peer: {0}")]
    CannotDeletePeer(#[source] anyhow::Error, String),

    #[error("Cannot find peer for email: {1}")]
    CannotFindPeerKey(#[source] anyhow::Error, String),

    #[error("Cannot find account for email: {1}")]
    CannotFindAccountKey(#[source] anyhow::Error, String),
}

// Transforms an error from some error type to the pep::Error.
macro_rules! wrap_err {
    ($e:expr, $err:ident, $msg:expr) => {
        $e.map_err(|err| {
            eprintln!("Error: {}: {}", err, $msg);
            anyhow::Error::from(Error::$err(
                anyhow::Error::from(err).into(),
                String::from($msg),
            ))
        })
    };
}

/// A autocrypt certificate store backend.
///
/// A backend, which provides access to a [autocrypt] certificate store.
///
/// [autocrypt]: https://autocrypt.org/
pub struct Autocrypt {
    // pub(crate) password: Option<Password>,
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
                conn.prepare_cached($sql),
                UnknownDbError,
                format!("preparing {} query", name)
            )
        }
    };
}

// Execute a query to load certificates, and actually load the
// certificates.
macro_rules! cert_query {
    ($stmt:expr, $args:expr, $err:expr) => {{
        let rows = wrap_err!(
            $stmt.query_map($args, Self::key_load),
            UnknownDbError,
            "executing query"
        )?;

        let mut results: Vec<_> = Vec::new();
        for row in rows {
            let (keydata, _private) = wrap_err!(row, UnknownError, "parsing result")?;
            match Cert::from_bytes(&keydata) {
                Ok(cert) => results.push(Cow::Owned(LazyCert::from(cert))),
                Err(err) => {
                    t!(
                        "Warning: unable to parse a certificate: {}\n{:?}",
                        err,
                        String::from_utf8(keydata)
                    );
                }
            }
        }

        if results.is_empty() {
            Err(anyhow::Error::from($err))
        } else {
            Ok(results)
        }
    }};
}

impl Autocrypt {
    /// Opens a `Autocrypt` certificate store.
    ///
    /// If `path` is `None`, then this uses the default location, which
    /// is `$XDG_DATA_HOME/pgp.cert.d/_autocrypt.sqlite`.
    ///
    /// This initializes the database, if necessary.
    pub fn open<P>(path: Option<P>) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        match path {
            Some(p) => Self::init_(Some(p.as_ref())),
            None => {
                let mut set = false;
                let mut keys_db = PathBuf::new();

                #[cfg(not(windows))]
                if cfg!(debug_assertions) {
                    if let Ok(pep_home) = std::env::var("AUTOCRYPT_HOME") {
                        set = true;
                        keys_db = PathBuf::from(pep_home);
                    }
                }

                if !set {
                    if let Some(home) = dirs::data_dir() {
                        keys_db = home
                    } else {
                        return Err(anyhow::anyhow!("Failed to find home directory"));
                    }
                }

                for n in KEYS_DB {
                    keys_db.push(n);
                }

                Self::init_(Some(&keys_db))
            }
        }
    }

    /// Returns a new `Autocrypt`.
    ///
    /// This uses an in-memory sqlite database.
    pub fn empty() -> Result<Self> {
        Self::init_in_memory()
    }

    // /// Returns a new `Autocrypt`.
    // ///
    // /// This uses an in-memory sqlite database, and loads it with the
    // /// keyring.
    // pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Self> {
    //     tracer!(TRACE, "Pep::from_bytes");
    //
    //     let raw_certs = RawCertParser::from_bytes(bytes)?.filter_map(|c| match c {
    //         Ok(c) => Some(c),
    //         Err(err) => {
    //             t!("Parsing raw certificate: {}", err);
    //             None
    //         }
    //     });
    //     Self::from_certs(raw_certs)
    // }

    // /// Returns a new `Autocrypt`.
    // ///
    // /// This uses an in-memory sqlite database, and loads it with the
    // /// specified certificates.
    // pub fn from_certs<'a, I>(certs: impl IntoIterator<Item = I>) -> Result<Self>
    // where
    //     I: Into<LazyCert<'a>>,
    // {
    //     let mut r = Self::init_in_memory()?;
    //     for cert in certs {
    //         r.update(Cow::Owned(cert.into()))
    //             .expect("implementation doesn't fail")
    //     }
    //
    //     Ok(r)
    // }

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
                        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
                ),
                InitCannotOpenDB,
                format!("Opening keys DB ('{}')", keys_db.display())
            )?
        } else {
            // Create an in-memory DB.
            wrap_err!(
                Connection::open_in_memory(),
                InitCannotOpenDB,
                "Creating in-memory keys DB"
            )?
        };

        wrap_err!(
            conn.execute_batch(
                "PRAGMA secure_delete=true;
                PRAGMA foreign_keys=true;
                PRAGMA locking_mode=NORMAL;
                PRAGMA journal_mode=WAL;"
            ),
            InitCannotOpenDB,
            format!("Setting pragmas on keys DB ('{}')", keys_db.display())
        )?;

        wrap_err!(
            conn.busy_timeout(BUSY_WAIT_TIME),
            InitCannotOpenDB,
            format!("Setting busy time ('{}')", keys_db.display())
        )?;

        wrap_err!(
            conn.create_collation("EMAIL", Self::email_cmp),
            InitCannotOpenDB,
            format!("Registering EMAIL collation function")
        )?;

        // TODO: Add current key? It's needed for sign (decrypt and sign) and update-key
        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS account (
                    address TEXT UNIQUE PRIMARY KEY NOT NULL COLLATE EMAIL, 
                    prefer INT,
                    enable INT,
                    primary_key TEXT
                );
                CREATE INDEX IF NOT EXISTS account_index
                    ON userids (address COLLATE EMAIL, primary_key))"
            ),
            InitCannotOpenDB,
            format!("Creating account table ('{}')", keys_db.display())
        )?;
        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS keys (
                    primary_key TEXT NOT NULL,
                    account TEXT NOT NULL,
                    secret BOOLEAN,
                    tpk BLOB,
                    PRIMARY KEY(primary_key, account),
                    FOREIGN KEY (account)
                            REFERENCES account(address),
                        ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS keys_index
                   ON keys (primary_key, secret)"
            ),
            InitCannotOpenDB,
            format!("Creating keys table ('{}')", keys_db.display())
        )?;

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
                   ON subkeys (subkey, primary_key)"
            ),
            InitCannotOpenDB,
            format!("Creating subkeys table ('{}')", keys_db.display())
        )?;

        wrap_err!(
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS peer (
                    address TEXT NOT NULL COLLATE EMAIL, 
                    account text,
                    last_seen INT8, 
                    timestamp INT8,
                    primary_key text,
                    gossip_timestamp INT8,
                    gossip_primary_key text,
                    prefer int,
                    counting_since int8,
                    count_have_ach int8,
                    count_no_ach int8,
                    bad_user_agent text,
                    PRIMARY KEY(address, account),
                    FOREIGN KEY(account) 
                            REFERENCES autocrypt_account(address),
                        ON DELETE CASCADE
                );"
                // CREATE INDEX IF NOT EXISTS peer_index
                //     ON peer (address COLLATE EMAIL, primary_key)"
            ),
            InitCannotOpenDB,
            format!("Creating peer table ('{}')", keys_db.display())
        )?;

        Ok(Autocrypt { conn })
    }

    // Returns a prepared statement for finding a certificate by
    // primary key fingerprint.
    sql_stmt!(
        cert_find_stmt,
        "SELECT tpk, secret FROM keys WHERE primary_key == ?"
    );

    // This only works for v4 certificates!  For v6 certificates the
    // keyid is the start of the fingerprint, not the end.
    sql_stmt!(
        cert_find_by_keyid_stmt,
        "SELECT tpk, secret FROM keys WHERE primary_key like '%' || ?"
        // "SELECT tpk, secret FROM keys WHERE primary_key like '%?%'"
    );

    // Returns a prepared statement for finding a key by primary key
    // fingerprint.
    sql_stmt!(
        tsk_find_stmt,
        "SELECT tpk, secret FROM keys
                 WHERE primary_key == ? and secret == 1"
    );

    // Returns a prepared statement for finding a certificate that
    // contains a key with the specified key id.  That is, this
    // matches on the primary key's key ID as well as any subkeys' key
    // ID.
    sql_stmt!(
        cert_find_with_key_stmt,
        "SELECT tpk, secret FROM subkeys
            LEFT JOIN keys
                ON subkeys.primary_key == keys.primary_key
            WHERE subkey == ?"
    );

    // Returns a prepared statement for finding a certificate with
    // secret key material that contains a key (with or without secret
    // key material) with the specified key id.  That is, this matches
    // on the primary key's key ID as well as any subkeys' key ID.
    sql_stmt!(
        tsk_find_with_key_stmt,
        "SELECT tpk, secret FROM subkeys
            LEFT JOIN keys
                ON subkeys.primary_key == keys.primary_key
            WHERE subkey == ? and keys.secret == 1"
    );

    sql_stmt!(
        tsk_find_with_account_stmt,
        "SELECT tpk FROM account
            LEFT JOIN keys
                ON account.primary_key == keys.primary_key
            WHERE account.address = ? and keys.secret == 1"
    );

    // Returns a prepared statement for finding a certificate with the
    // specified email address.
    sql_stmt!(
        cert_find_by_email_stmt,
        "SELECT tpk, secret FROM account
            LEFT JOIN keys
                ON account.address == keys.account
            WHERE address == ? and private == 1"
    );

    sql_stmt!(
        cert_find_by_peer_stmt,
        "SELECT tpk, secret FROM peer
            LEFT JOIN keys
                ON peer.primary_key == keys.primary_key
            WHERE address == ? and account == ?"
    );

    sql_stmt!(
        cert_find_by_peer_gossip_stmt,
        "SELECT tpk, secret FROM peer
            LEFT JOIN keys
                ON peer.gossip_primary_key == keys.primary_key
            WHERE address == ? and account == ?"
    );

    sql_stmt!(
        get_account_stmt,
        "SELECT address,
            prefer,
            enable,
        FROM account
            LEFT JOIN keys
                ON peer.gossip_primary_key == keys.primary_key
            WHERE address == ? and account == ?"
    );

    sql_stmt!(
        get_peer_stmt,
        "SELECT address,
            account,
            last_seen,
            timestamp,
            primary_key,
            gossip_timestamp,
            gossip_primary_key,
            prefer
        FROM peer
            LEFT JOIN keys
                ON peer.gossip_primary_key == keys.primary_key
            WHERE address == ? and account == ?"
    );

    // Returns a prepared statement for returning all the fingerprints
    // of all certificates in the database.
    sql_stmt!(cert_list_stmt, "select DISTINCT primary_key from keys");

    // Returns a prepared statement for returning all certificates in
    // the database.
    sql_stmt!(cert_all_stmt, "select DISTINCT tpk, secret from keys");

    // Returns a prepared statement for returning all certificates in
    // the database, which contain secret key material.
    sql_stmt!(
        tsk_all_stmt,
        "select DISTINCT tpk, secret from keys where secret = 1"
    );

    // Returns a prepared statement for updating the keys table.
    sql_stmt!(
        cert_save_insert_primary_stmt,
        "INSERT OR REPLACE INTO keys (primary_key, account, secret, tpk)
                VALUES (?, ?, ?, ?)"
    );

    // Returns a prepared statement for updating the subkeys table.
    sql_stmt!(
        cert_save_insert_subkeys_stmt,
        "INSERT OR REPLACE INTO subkeys (subkey, primary_key)
                VALUES (?, ?)"
    );

    sql_stmt!(
        account_save_insert_stmt,
        "INSERT OR REPLACE INTO account (address, prefer, enable)
                VALUES (?, ?, ?)"
    );

    sql_stmt!(
        account_set_key_stmt,
        "UPDATE account 
            primary_key
            where address = ?"
    );

    // Returns a prepared statement for updating the userids table.
    sql_stmt!(
        peer_save_insert_stmt,
        "INSERT OR REPLACE INTO peer (
            address,
            account,
            last_seen,
            timestamp,
            primary_key,
            gossip_timestamp,
            gossip_primary_key,
            prefer)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );

    // Returns a prepared statement for deleting a certificate.
    //
    // Note: due to the use of foreign keys, when a key is removed
    // from the keys table, the subkeys and userids tables are also
    // automatically update.
    sql_stmt!(cert_delete_stmt, "DELETE FROM keys WHERE primary_key = ?");

    sql_stmt!(delete_account_stmt, "DELETE FROM account where address = ?");

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

        let a_email = a_userid.email_normalized().or_else(|_| a_userid.uri()).ok();
        let b_email = b_userid.email_normalized().or_else(|_| b_userid.uri()).ok();

        match (a_email, b_email) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(&b),
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
    pub fn tsk_lookup_by_email(&self, account_email: &str) -> Result<Cow<LazyCert>> {
        tracer!(TRACE, "Autocrypt::tsk_lookup_by_email");

        let mut stmt = Self::tsk_find_stmt(&self.conn)?;

        let r = cert_query!(
            stmt,
            [account_email],
            StoreError::NoMatches(account_email.to_owned())
        )?;
        let r = r
            .into_iter()
            .next()
            .ok_or_else(|| account_email.to_owned())?;
        Ok(r)
    }

    fn account(&self, account_mail: &str) -> Result<Account> {
        todo!()
    }
    fn set_account(&self, acc: &Account) -> Result<()> {
        todo!()
    }

    fn peer(&self, account_mail: &str, peer_mail: &str) -> Result<Peer> {
        todo!()
    }

    fn set_peer(&self, peer: &Peer) {
        todo!()
    }

    fn private_key(&self, account_mail: &str) -> Result<Cert> {
        todo!()
    }

    pub fn set_prefer(&self, account_mail: &str, prefer: Prefer) -> Result<()> {
        let mut account = self.account(account_mail)?;
        account.prefer = prefer;
        self.set_account(&account)
    }

    /// Get the prefer setting for an account
    pub fn prefer(&self, account_mail: &str) -> Result<Prefer> {
        let account = self.conn.account(account_mail)?;
        Ok(account.prefer)
    }

    /// Set enable for an account
    /// These are just internal settings and doesn't effect runtime.
    /// Functions such as recommend does not check the enable and it's up
    /// the user to do so.
    pub fn set_enable(&self, account_mail: &str, enable: bool) -> Result<()> {
        tracer!(TRACE, "Autocrypt::set_enable");

        let mut account = self.account(account_mail)?;
        account.enable = enable;
        self.set_account(&account)
    }

    /// Get enable for an account
    pub fn enable(&self, account_mail: &str) -> Result<bool> {
        let account = self.account(account_mail)?;
        Ok(account.enable)
    }

    fn gen_cert(&self, account_mail: &str, now: SystemTime) -> Result<(Cert, Signature)> {
        let mut builder = CertBuilder::new();
        builder = builder.add_userid(account_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_signing_subkey();
        // We set storage_encryption so we can store drafts
        builder = builder.add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            None,
        );

        builder = builder.set_password(self.password.clone());

        builder.generate()
    }

    /// Update the private key the account for our mail. If the current key is
    /// is still usable, no update is done.
    pub fn update_private_key(&self, policy: &dyn Policy, account_mail: &str) -> Result<()> {
        let now = SystemTime::now();

        let mut account = if let Ok(mut account) = self.account(account_mail) {
            let key = self.private_key(account_mail)?;
            if key.primary_key().with_policy(policy, now).is_ok() {
                return Ok(());
            }
            account
        } else {
            let account = Account::new(account_mail, None);
            self.set_account(&account)?;
            account
        };

        let (cert, _) = self.gen_cert(account_mail, now)?;
        account.fpr = Some(cert.fingerprint());
        self.set_account(&account)?;

        Ok(())
    }

    /// Update when we last time we saw an email that didn't contain
    /// autocrypt field.
    /// * `account_mail` - The user account or optional None if we are in wildmode
    /// * `peer_mail` - Peer we want to update
    /// * `effective_date` - The date we want to update to. This should be the date from the email.
    pub fn update_last_seen(
        &self,
        account_mail: &str,
        peer_mail: &str,
        effective_date: DateTime<Utc>,
        user_agent: &str
    ) -> Result<bool> {

        if effective_date > Utc::now() {
            return Err(anyhow::anyhow!("Date is in the future"));
        }

        let mut peer = self.peer(account_mail, peer_mail);

        match peer {
            Err(err) => {
                match err.kind() {
                    CannotFindPeerKey => {
                        Ok(false)
                    }
                    _ => return Err(err)
                }
            }
            Ok(peer) => {
                if peer.last_seen < effective_date {
                    peer.last_seen = effective_date;
                }

                peer.user_agent = Some(user_agent);
                if peer.counting_since < effective_date {
                    peer.count_no_ach = peer.count_no_arch + 1;
                }
                if peer.counting_since < peer.timestamp && 
                    peer.counting_since + Duration::days(35) < effective_date {

                    peer.count_no_ach = 1;
                    peer.count_have_ach = 0;
                    peer.counting_since = peer.last_seen;
                }

                self.set_peer(&peer)?;
                Ok(true)
            }
        }
    }

    /// Update or install a peer from an email with an autocrypt header.
    /// * `account_mail` - The user account or optional None if we are in wildmode
    /// * `peer_mail` - Peer address we want to update or install
    /// * `cert` - A cert (gossip or normal)
    /// * `prefer` - If the user prefer encryption or not
    /// * `effective_date` - The efficitve date in the message
    /// * `gossip` - if the peer exchange is gossip or not.
    pub fn update_peer(
        &self,
        account_mail: &str,
        peer_mail: &str,
        cert: &Cert,
        prefer: Prefer,
        effective_date: DateTime<Utc>,
        gossip: bool,
    ) -> Result<bool> {
        if account_mail == peer_mail {
            return Err(anyhow::anyhow!(
                "Setting a peer for your private key isn't allowed" 
            ));
        }

        let peer = self.peer(account_mail, peer_mail);

        match peer {
            Err(err) => {
                match err.kind() {
                    CannotFindPeerKey => {
                        let peer = Peer::new(peer_mail, account_mail, effective_date, cert, gossip, prefer);
                        self.conn.set_peer(&peer)?;
                        Ok(true)
                    }
                    _ => return Err(err)
                }
            }
            Ok(mut peer) => {
                if effective_date <= peer.last_seen {
                    return Ok(false);
                }

                peer.last_seen = effective_date;

                if !gossip {
                    if peer.timestamp.is_none() || 
                        effective_date > peer.timestamp.unwrap()
                    {
                        peer.timestamp = Some(effective_date);
                        peer.cert_fpr = Some(cert.fingerprint());

                        peer.account = account_mail.to_owned();
                        peer.prefer = prefer;

                    }
                } else if peer.gossip_timestamp.is_none() ||
                    effective_date > peer.gossip_timestamp.unwrap()
                {
                    peer.gossip_timestamp = Some(effective_date);
                    peer.gossip_fpr = Some(cert.fingerprint());

                    peer.account = account_mail.to_owned();
                }
                self.conn.update_peer(&peer, self.wildmode)?;

                self.conn.set_cert(&peer.account, &cert)?;

                Ok(true)
            }
        }
    }


    /// Make a setup message. Setup messages are used to transfer your private key
    /// from one autocrypt implementation to another. Making it easier to change MUA.
    pub fn setup_message(&self, account_mail: &str) -> Result<AutocryptSetupMessage> {
        let cert = self.private_key(account_mail)?;
        // let mut stmt = Self::cert_find_by_email_stmt(&self.conn)?;
        // let cert = cert_query!(stmt, [&account_mail], StoreError::NoMatches(email.into()))?;

        // if let Some(ref password) = self.password {
        //     let open = remove_password(account.cert, password)?;
        //     Ok(AutocryptSetupMessage::new(open))
        // } else {
        Ok(AutocryptSetupMessage::new(cert))
        // }
    }



    /// Generate an autocryptheader to be inserted into a email header with our public key.
    pub fn header(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        prefer: Prefer,
    ) -> Result<AutocryptHeader> {
        let cert = self.private_key(account_mail)?;
        // TODO: get the corret stuff

        AutocryptHeader::new_sender(policy, &cert, account_mail, prefer)
    }

    /// Generate a autocryptheader to be inserted into a email header
    /// with gossip information about peers. Gossip is used to spread keys faster.
    /// This should be called once for each gossip header we want spread.
    /// * `account_mail` - The user account
    /// * `peer_mail` - peer we want to generate gossip for
    pub fn gossip_header(
        &self,
        account_mail: &str,
        peer_mail: &str,
        policy: &dyn Policy,
    ) -> Result<AutocryptHeader> {
        // let cert = self.key(peer_mail);
        let peer = self.peer(account_mail, peer_mail);
        // let stmt = let mut stmt = Self::cert_find_by_fpr_stmt(&self.conn)?;
        let mut header = if peer.primary_key.is_some() {
            // let cert = cert_query!(stmt, [&account_mail], StoreError::NoMatches(email.into()))?;
            let cert = self.get_peer_cert(&peer);
            AutocryptHeader::new_sender(policy, cert, &peer.address, peer.prefer)
        } else if peer.gossip.is_some() {
            // let cert = cert_query!(stmt, [&account_mail], StoreError::NoMatches(email.into()))?;
            let cert = self.get_peer_cert(&peer);
            AutocryptHeader::new_sender(policy, cert, &peer.address, None)
        } else {
            return StoreError::NoMatches("No primary or gossip key".to_string());
        };
        header.header_type = AutocryptHeaderType::Gossip;
        Ok(header)

        // if let Some(ref cert) = peer.cert {
        //     if let Ok(mut header) =
        //     AutocryptHeader::new_sender(policy, cert, &peer.address, peer.prefer)
        //     {
        //         header.header_type = AutocryptHeaderType::Gossip;
        //         return Ok(header);
        //     }
        // }
        // if let Some(ref cert) = peer.gossip_cert {
        //     if let Ok(mut header) = AutocryptHeader::new_sender(policy, cert, &peer.address, None) {
        //         header.header_type = AutocryptHeaderType::Gossip;
        //         return Ok(header);
        //     }
        // }
        // Err(anyhow::anyhow!("Can't find key to create gossip data"))
        // gossip_helper(&peer, policy)
    }

    /// Returns the matching TSK.
    ///
    /// Like [`Store::lookup_by_cert_fpr`], but only returns
    /// certificates with private key material.
    pub fn current_peer_key_by_email(&self, account_mail: &str, peer_email: &str) -> Result<Cow<LazyCert>> {
        tracer!(TRACE, "Autocrypt::current_peer_key_by_email");

        let mut stmt = Self::tsk_find_stmt(&self.conn)?;

        let r = cert_query!(
            stmt,
            [peer_email],
            StoreError::NotFound(KeyHandle::from(fpr))
        )?;
        let r = r
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::NotFound(KeyHandle::from(fpr)))?;
        Ok(r)
    }

    /// Install a setup message into the system. If the key is usable we install the key.
    /// If the account doesn't exist, it's created.
    /// It doesn't care if the cert is older than the current, it will be overwritten anyways.
    pub fn install_message(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        mut message: AutocryptSetupMessageParser,
        password: &Password,
    ) -> Result<()> {
        message.decrypt(password)?;
        let decrypted = message.parse()?;
        let mut cert = decrypted.into_cert();

        let now = SystemTime::now();
        cert.primary_key().with_policy(policy, now)?;

        if let Some(ref password) = self.password {
            cert = set_password(cert, password)?
        }

        let account = if let Ok(mut account) = self.account(account_mail) {
            // We don't check which cert is newer etc.
            // We expect the user to know what he/she is doing
            account.cert = cert;
            account
        } else {
            Account::new(account_mail, cert)
        };

        // let peer = self
        //     .conn
        //     .peer(account_mail, Selector::Email(account_mail))
        //     .ok();
        //
        // self.update_peer_forceable(
        //     account_mail,
        //     account_mail,
        //     peer,
        //     &account.cert,
        //     account.prefer,
        //     now.into(),
        //     false,
        //     true,
        // )?;
        Ok(())
    }

    pub fn recommend(
        &self,
        account_mail: &str,
        target_mail: &str,
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        if let Some(peer) = peer {
            let pre = peer.preliminary_recommend(policy);
            if pre.encryptable() && reply_to_encrypted {
                return UIRecommendation::Encrypt;
            }
            if pre.preferable() && peer.prefer.encrypt() && prefer.encrypt() {
                return UIRecommendation::Encrypt;
            }
            return pre;
        }
        UIRecommendation::Disable
    }

    /// multi_recommend runs recommend on multiple peers.
    /// * `account_mail` - The user account
    /// * `peers_mail` - Peers we want to check if it's safe to encrypt to.
    /// * `reply_to_encrypted` - If we reply to an encrypted email.
    /// * `prefer` - our account setting.
    pub fn multi_recommend(
        &self,
        account_mail: &str,
        target_emails: &[&str],
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: Prefer,
    ) -> UIRecommendation {
        target_emails
            .iter()
            .map(|m| self.recommend(account_mail, m, policy, reply_to_encrypted, prefer))
            .sum()
    }

    /// Returns the matching TSK.
    ///
    /// Like [`Store::lookup_by_cert_fpr`], but only returns
    /// certificates with private key material.
    pub fn tsk_lookup_by_cert_fpr(&self, fpr: &Fingerprint) -> Result<Cow<LazyCert>> {
        tracer!(TRACE, "Autocrypt::tsk_lookup_by_cert_fpr");

        let mut stmt = Self::tsk_find_stmt(&self.conn)?;

        let r = cert_query!(
            stmt,
            [fpr.to_hex()],
            StoreError::NotFound(KeyHandle::from(fpr))
        )?;
        let r = r
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::NotFound(KeyHandle::from(fpr)))?;
        Ok(r)
    }

    /// Returns the matching TSK.
    ///
    /// Like [`Store::lookup_by_key`], but only returns certificates
    /// with private key material.
    pub fn tsk_lookup_by_key(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert>>> {
        tracer!(TRACE, "Autocrypt::tsk_lookup_by_key");

        let mut stmt = Self::tsk_find_with_key_stmt(&self.conn)?;

        let keyid = KeyID::from(kh).to_hex();
        t!("({})", keyid);

        cert_query!(stmt, [keyid], StoreError::NotFound(kh.clone()))
    }

    /// Returns all of the TSKs.
    ///
    /// Like [`Store::certs`], but only returns certificates with
    /// private key material.
    pub fn tsks<'b>(&'b self) -> Box<dyn Iterator<Item = Cow<'b, LazyCert>> + 'b> {
        tracer!(TRACE, "Autocrypt::tsks");

        let inner = || -> Result<Vec<_>> {
            let mut stmt = Self::tsk_all_stmt(&self.conn)?;
            cert_query!(stmt, [], StoreError::NoMatches("EOF".into()))
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
    pub fn account_delete(&mut self, account: &str) -> Result<()> {
        let changes = wrap_err!(
            Self::account_delete_stmt(&self.conn)?.execute(params![account]),
            CannotDeleteAccount,
            format!("Deleting {}", account)
        )?;

        if changes == 0 {
            Err(StoreError::NotFound(KeyHandle::from(account.clone())).into())
        } else {
            Ok(())
        }
    }

    /// Deletes the specified certificate from the database.
    ///
    /// If the certificate contains any private key material, this is
    /// also deleted.
    ///
    /// Returns an error if the specified certificate is not found.
    pub fn account_delete(&mut self, account: &str) -> Result<()> {
        let changes = wrap_err!(
            Self::account_delete_stmt(&self.conn)?.execute(params![account]),
            CannotDeletePeer,
            format!("Deleting {}", account)
        )?;

        if changes == 0 {
            Err(StoreError::NotFound(KeyHandle::from(account.clone())).into())
        } else {
            Ok(())
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
            Self::cert_delete_stmt(&self.conn)?.execute(params![fpr.to_hex()]),
            CannotDeleteKey,
            format!("Deleting {}", fpr)
        )?;

        if changes == 0 {
            Err(StoreError::NotFound(KeyHandle::from(fpr.clone())).into())
        } else {
            Ok(())
        }
    }
}

impl<'a> Store<'a> for Autocrypt {
    /// Returns the certificates whose fingerprint matches the handle.
    ///
    /// Returns [`StoreError::NotFound`] if no certificate is found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn lookup_by_cert(&self, kh: &KeyHandle) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Autocrypt::lookup_by_cert");

        let mut stmt = match kh {
            KeyHandle::Fingerprint(_) => Self::cert_find_stmt(&self.conn)?,
            KeyHandle::KeyID(_) => Self::cert_find_by_keyid_stmt(&self.conn)?,
        };

        cert_query!(stmt, [kh.to_hex()], StoreError::NotFound(kh.clone()))
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
        tracer!(TRACE, "Autocrypt::lookup_by_key");

        let mut stmt = Self::cert_find_with_key_stmt(&self.conn)?;

        let keyid = KeyID::from(kh).to_hex();
        t!("({})", keyid);

        let mut certs: Vec<Cow<LazyCert<'a>>> =
            cert_query!(stmt, [keyid], StoreError::NotFound(kh.clone()))?;

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
    fn select_userid(
        &self,
        query: &UserIDQueryParams,
        pattern: &str,
    ) -> Result<Vec<Cow<LazyCert<'a>>>> {
        tracer!(TRACE, "Autocrypt::select_userid");

        let results: Vec<Cow<LazyCert>>;

        match (
            query.email(),
            query.ignore_case(),
            query.anchor_start(),
            query.anchor_end(),
        ) {
            // Email.
            (true, _, true, true) => match UserIDQueryParams::is_email(pattern) {
                Ok(email) => return self.lookup_by_email(&email),
                Err(err) => {
                    t!("{:?} is not a valid email address: {}", pattern, err);
                    return Ok(vec![]);
                }
            },

            _ => {
                // Iterate over all the certificates, and return those
                // that match.
                //
                // This is potentially very expensive.  Where possible
                // we should use the the indices to reduce false
                // positives.

                results = self
                    .certs()
                    .filter(|cert| query.check_lazy_cert(&cert, pattern))
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
        tracer!(TRACE, "Autocrypt::lookup_by_email");

        let userid = crate::email_to_userid(&email)?;
        let email = userid.email_normalized()?.expect("have one");

        let mut stmt = Self::cert_find_by_email_stmt(&self.conn)?;

        cert_query!(stmt, [&email], StoreError::NoMatches(email.into()))
    }

    /// Lists all of the certificates.
    ///
    /// If a backend is not able to enumerate all the certificates,
    /// then it should return those that it knows about.  For
    /// instance, some keyservers allow certificates to be looked up
    /// by fingerprint, but not to enumerate all of the certificates.
    /// Thus, a user must not assume that if a certificate is not
    /// returned by this function, it cannot be found by name.
    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = Fingerprint> + 'b> {
        tracer!(TRACE, "Autocrypt::fingerprints");

        let inner = || -> Result<Vec<Fingerprint>> {
            let mut stmt = Self::cert_list_stmt(&self.conn)?;

            let rows = wrap_err!(
                stmt.query_map([], |row: &Row| {
                    let fpr: String = row.get(0)?;
                    Ok(fpr)
                }),
                UnknownDbError,
                "executing query"
            )?;

            let mut results: Vec<_> = Vec::new();
            for row in rows {
                let fpr = wrap_err!(row, UnknownError, "parsing result")?;
                match fpr.parse::<Fingerprint>() {
                    Ok(fpr) => results.push(fpr),
                    Err(err) => {
                        t!(
                            "Warning: unable to parse {:?} as a fingerprint: {}",
                            fpr,
                            err
                        );
                    }
                }
            }

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
    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item = Cow<'b, LazyCert<'a>>> + 'b>
    where
        'a: 'b,
    {
        tracer!(TRACE, "Autocrypt::certs");

        let inner = || -> Result<Vec<_>> {
            let mut stmt = Self::cert_all_stmt(&self.conn)?;
            cert_query!(stmt, [], StoreError::NoMatches("EOF".into()))
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

// impl<'a> StoreUpdate<'a> for Pep {
//     fn update_by<'ra>(
//         &'ra mut self,
//         cert: Cow<'ra, LazyCert<'a>>,
//         merge_strategy: &mut dyn MergeCerts<'a, 'ra>,
//     ) -> Result<Cow<'ra, LazyCert<'a>>> {
//         tracer!(TRACE, "Pep::update_by");
//
//         let fpr = cert.fingerprint();
//         t!("Updating {}", fpr);
//
//         let tx = wrap_err!(
//             self.conn.transaction(),
//             UnknownDbError,
//             "starting transaction"
//         )?;
//
//         // If the certificate already exists, we merge the existing
//         // variant with the new variant.
//         let r = wrap_err!(
//             Self::cert_find_stmt(&tx)?
//                 .query_row(&[&fpr.to_hex()], Self::key_load)
//                 .optional(),
//             UnknownDbError,
//             "executing query"
//         )?;
//
//         let existing = if let Some((existing_keydata, _)) = r {
//             t!(
//                 "Got {} bytes of existing certificate data",
//                 existing_keydata.len()
//             );
//             match Cert::from_bytes(&existing_keydata) {
//                 Ok(existing) => Some((existing_keydata, LazyCert::from(existing))),
//                 Err(err) => {
//                     t!(
//                         "Failed to parse existing data for {} (overwriting): {}",
//                         fpr,
//                         err
//                     );
//                     None
//                 }
//             }
//         } else {
//             t!("New certificate");
//             None
//         };
//
//         let merged = if let Some((_, existing_cert)) = &existing {
//             t!("Updating {}", fpr);
//
//             merge_strategy
//                 .merge_public(cert, Some(Cow::Borrowed(existing_cert)))
//                 .with_context(|| format!("Merging two versions of {}", fpr))?
//         } else {
//             t!("Inserting {}", fpr);
//
//             merge_strategy.merge_public(cert, None)?
//         };
//
//         let merged = merged
//             .into_owned()
//             .into_cert()
//             .context("Resolving merged certificate")?;
//
//         let mut merged_keydata = Vec::new();
//         wrap_err!(
//             merged.as_tsk().serialize(&mut merged_keydata),
//             UnknownDbError,
//             "Serializing certificate"
//         )?;
//
//         let new_or_changed = if let Some((existing_keydata, _)) = &existing {
//             &merged_keydata != existing_keydata
//         } else {
//             true
//         };
//
//         if !new_or_changed {
//             t!("Data unchanged.");
//             return Ok(Cow::Owned(LazyCert::from(merged)));
//         }
//
//         t!("Serializing {} bytes ({:X})", merged_keydata.len(), {
//             use std::collections::hash_map::DefaultHasher;
//             use std::hash::Hasher;
//
//             let mut hasher = DefaultHasher::new();
//
//             hasher.write(&merged_keydata);
//             hasher.finish()
//         });
//
//         // Save the certificate.
//         {
//             let mut stmt = Self::cert_save_insert_primary_stmt(&tx)?;
//             wrap_err!(
//                 stmt.execute(params![fpr.to_hex(), merged.is_tsk(), &merged_keydata]),
//                 UnknownDbError,
//                 "Executing cert_save_insert_primary"
//             )?;
//         }
//
//         // Update the subkey table.
//         {
//             let mut stmt = Self::cert_save_insert_subkeys_stmt(&tx)?;
//             for (i, ka) in merged.keys().enumerate() {
//                 t!(
//                     "  {}key: {} ({} secret key material)",
//                     if i == 0 { "primary " } else { "sub" },
//                     ka.keyid(),
//                     if ka.has_secret() { "has" } else { "no" }
//                 );
//                 wrap_err!(
//                     stmt.execute(params![ka.keyid().to_hex(), fpr.to_hex()]),
//                     UnknownDbError,
//                     "Executing cert save insert subkeys"
//                 )?;
//             }
//         }
//
//         // Update the userid table.
//         {
//             let mut stmt = Self::cert_save_insert_userids_stmt(&tx)?;
//
//             for ua in merged.userids() {
//                 let uid = if let Ok(Some(email)) = ua.email_normalized() {
//                     email
//                 } else if let Ok(Some(uri)) = ua.uri() {
//                     uri
//                 } else {
//                     continue;
//                 };
//                 t!("  User ID: {}", uid);
//
//                 wrap_err!(
//                     stmt.execute(params![uid, fpr.to_hex()]),
//                     UnknownDbError,
//                     "Executing cert save insert userids"
//                 )?;
//             }
//         }
//
//         wrap_err!(tx.commit(), UnknownDbError, "committing transaction")?;
//
//         t!("saved");
//
//         Ok(Cow::Owned(LazyCert::from(merged)))
//     }
// }
