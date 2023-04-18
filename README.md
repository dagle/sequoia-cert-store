An OpenPGP certificate store abstraction and implementation.

This crates provides a unified, high-level API for different
certificate stores via the `Store` and `StoreUpdate` traits.  It also
provides a number of helper functions and data structures, like
`UserIDIndex` to help implement this functionality.  Finally, the
`CertStore` data structure combines multiple certificate backends in a
transparent way to users.

This crate supports multiple backends: `CertD` uses an [OpenPGP
Certificate Directory].  `Certs` manages a bunch of certificates
in-memory.  It can be loaded with certificates from a keyring, a
keybox, a database, etc.  It can also be used as the basis for a new
backend, which actually writes changes back to the underlying store.
`Pep` provides access to a [pEp] certificate store.  Finally, there is a
key server backend, which can fetch certificates via HKPS and WKD.

  [OpenPGP Certificate Directory]: https://crates.io/crates/openpgp-cert-d
  [pEp]: https://gitea.pep.foundation/pEp.foundation/pEpEngine

## Usage

To use `sequoia-cert-store` from your project, you should add the following
to your crate's `Cargo.toml`:

```toml
[dependencies]
sequoia-cert-store = "0.1"
sequoia-openpgp = { version = "1.0.0", default-features = false }
```

To compile your crate you would then run:

```
$ cargo build --release --features sequoia-openpgp/crypto-default
$ cargo test --features sequoia-openpgp/crypto-default
$ cargo doc --no-deps --features sequoia-openpgp/crypto-default
```

If you do not disable the use of `sequoia-openpgp`'s default features,
then `sequoia-openpgp` will select the default cryptographic backend,
and your users won't be able to easily compile your crate with a
different cryptographic backend.

`sequoia-openpgp` currently uses Nettle as its default cryptographic
backend.  `sequoia-openpgp` also supports OpenSSL
(`sequoia-openpgp/crypto-openssl`), Windows CNG
(`sequoia-openpgp/crypto-cng`), and Rust Crypto
(`sequoia-openpgp/crypto-rust`).  For more information about building
`sequoia-openpgp`, please refer to [`sequoia-openpgp`'s README].  This
also includes information about the different backends' [build
requirements].

  [`sequoia-openpgp`'s README]: https://gitlab.com/sequoia-pgp/sequoia#features
  [build requirements]: https://gitlab.com/sequoia-pgp/sequoia#building-sequoia


# License

sequoia-cert-store is distributed under the terms of LGPL 2.0 or later.

See [LICENSE.txt](LICENSE.txt) and [CONTRIBUTING.md](CONTRIBUTING.md)
for details.
