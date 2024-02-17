# A Lightweight Port of Google's Tink Library

Rust lacked a simple port of Tink that I could use in my rewrite of a Java service to Rust.
An issue with existing ports is that they operate on `Box<dyn Trait>` values that aren't
`Send`.

The number one design goal of this library is that all types that the library operates on
are both `Send` and `Clone` making them easy to use in async servers.

The current version ONLY supports AES-GCM and Ed25519 signatures. This happens to be what
I personally needed. It's not difficult to add support for missing primitives and PRs are
welcome.
