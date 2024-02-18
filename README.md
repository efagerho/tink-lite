# A Lightweight Port of Google's Tink Library

Rust lacked a simple port of Tink that I could use in my rewrite of a Java service to Rust.
An issue with existing ports is that they operate on `Box<dyn Trait>` values that aren't
`Send` nor `Sync`.

The number one design goal of this library is that all types that the library operates on
are both `Send`, `Sync` and `Clone` making them easy to use in async servers.

Limitations:

1. Only supports key with Tink or Legacy prefixes.
1. Only AES-GCM currently supported.
1. Only supportes key loading operations, i.e. you have to create your keys elsewhere.
1. No support for KMS etc.
1. Only supports loading of plaintext keys.

The library has been designed with the following use-case in mind:

1. A server receiving all its keys in environment variables, e.g. AWS ECS.
1. Server does not need to generate any new keys, e.g. keys are rotated by generating
   key material elsewhere and restarting the service.

TODO:

1. The TinkError type needs an actual implementation and error handling needs to be properly implemented.
1. Decrypt operations are not implemented
1. Tests are missing, so code might be horribly broken
