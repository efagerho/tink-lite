# A Lightweight Port of Google's Tink Library

Rust lacked a simple port of Tink that I could use in my rewrite of a Java service to Rust.
An issue with existing ports is that they operate on `Box<dyn Trait>` values that aren't
`Send`.

The number one design goal of this library is that all types that the library operates on
are both `Send` and `Clone` making them easy to use in async servers.

WIP and code is still broken.

TODO:

1. Uses fixed IV, so needs to actually sample it.
1. Doesn't write a valid prefix to the ciphertexts, so they are broken.
1. Doesn't parse the prefix on decrypt to find the right key.
1. The TinkError type needs an actual implementation and error handling needs to be properly implemented.
