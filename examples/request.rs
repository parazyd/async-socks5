/* This file is part of async-socks5
 *
 * Copyright (C) 2023 parazyd <parazyd@dyne.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::net::{Shutdown, ToSocketAddrs};

use async_socks5::{Socks5Client, Socks5Error};
use smol::io::{AsyncReadExt, AsyncWriteExt};

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n";

fn main() -> Result<(), Socks5Error> {
    smol::block_on(async {
        // Example using system DNS resolution
        // Here I use the Tor SOCKS5 proxy.
        let mut addr = "icanhazip.com:80".to_socket_addrs()?;
        let addr = addr.next().unwrap();

        let mut stream = Socks5Client::connect("127.0.0.1:9050", &addr, None).await?;
        stream.write_all(REQUEST).await?;

        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await?;
        stream.shutdown(Shutdown::Both)?;

        println!("{}", String::from_utf8(buf.clone()).unwrap());

        // Example using SOCKS5 DNS resolution
        // Here I also use the Tor SOCKS5 proxy.
        let mut stream =
            Socks5Client::connect_with_domain("127.0.0.1:9050", "icanhazip.com", 80, None).await?;
        stream.write_all(REQUEST).await?;

        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await?;
        stream.shutdown(Shutdown::Both)?;

        println!("{}", String::from_utf8(buf).unwrap());

        // Example using Authentication.
        // Here I use dante sockd with authentication forwarding to the Tor proxy.
        //
        // Simple sockd.conf:
        // ```
        // logoutput: syslog
        // internal: 127.0.0.1 port = 1080
        // external: 127.0.0.1
        // method: username
        // user.privileged: sockd
        // user.notprivileged: sockd
        // client pass {
        //     from: 0/0 to: 0/0
        //     log: error connect disconnect
        // }
        // socks pass {
        //     from: 0/0 to: 0/0
        //     log: error connect disconnect
        // }
        // route {
        //     from: 0.0.0.0/0 to: 0.0.0.0/0 via: 127.0.0.1 port = 9050
        //     proxyprotocol: socks_v4 socks_v5
        //     method: none
        // }
        // ```
        let mut stream = Socks5Client::connect_with_domain(
            "127.0.0.1:1080",
            "icanhazip.com",
            80,
            Some(("user", "pass")),
        )
        .await?;

        stream.write_all(REQUEST).await?;

        let mut buf = vec![0u8; 1024];
        let _ = stream.read(&mut buf).await?;
        stream.shutdown(Shutdown::Both)?;

        println!("{}", String::from_utf8(buf).unwrap());

        Ok(())
    })
}
