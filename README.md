An OpenPGP certificate store abstraction and implementation.

This crates provides a unified, high-level API for different
certificate stores via the `Store` trait.  It also provides a number
of helper functions and data structures, like `UserIDIndex` to help
implement this functionality.

The `CertStore` data structure combines multiple certificate backends in
a transparent way to users.

It supports multiple backends (a cert-d, a keyring, a keybox, an
in-memory, and a key server backend), and the backends can be layered.
