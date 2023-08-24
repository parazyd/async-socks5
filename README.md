async-socks5
============

A minimal TCP-only async SOCKS5 client for Rust using `async-net`
and `futures-lite` crates written in <150 SLOC.

Usage example in [`examples/request.rs`](examples/request.rs).
Docs can be found by reading the rustdoc in [`src/lib.rs`](src/lib.rs).

The library supports SOCKS5 connections with and without proxy
authentication, as well as resolving DNS through the proxy by using
the `Socks5Client::connect_with_domain` function.

`async-socks5` is best used with Tor.
