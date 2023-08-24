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

use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

use async_net::TcpStream;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

/// Socks5 error types
#[derive(Clone, Debug)]
pub enum Socks5Error {
    HandshakeFailed,
    ConnectionFailed,
    UnexpectedResponse,
    UnsupportedAddressType,
    AuthenticationFailed,
    IoError(std::io::ErrorKind),
}

impl From<std::io::Error> for Socks5Error {
    fn from(err: std::io::Error) -> Self {
        Socks5Error::IoError(err.kind())
    }
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeFailed => write!(f, "handhake failed"),
            Self::ConnectionFailed => write!(f, "connection failed"),
            Self::UnexpectedResponse => write!(f, "unexpected response"),
            Self::UnsupportedAddressType => write!(f, "unsupported address type"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
            Self::IoError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Socks5Error {}

/// Supported address types for the SOCKS5 client
pub enum AddrType {
    IPv4,
    DomainName,
    IPv6,
}

impl AddrType {
    fn as_byte(&self) -> u8 {
        match self {
            AddrType::IPv4 => 0x01,
            AddrType::DomainName => 0x03,
            AddrType::IPv6 => 0x04,
        }
    }
}

/// Socks5 client instance
pub struct Socks5Client;

impl Socks5Client {
    /// Internal authentication method to authenticate to the proxy with
    /// given credentials (username and password).
    async fn authenticate(
        stream: &mut TcpStream,
        credentials: &(&str, &str),
    ) -> Result<(), Socks5Error> {
        let mut request = vec![0x01]; // Version
        request.push(credentials.0.len() as u8);
        request.extend_from_slice(credentials.0.as_bytes());
        request.push(credentials.1.len() as u8);
        request.extend_from_slice(credentials.1.as_bytes());

        stream.write_all(&request).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[1] != 0x00 {
            return Err(Socks5Error::AuthenticationFailed);
        }

        Ok(())
    }

    /// Internal handshake method to initialize the connection with a
    /// SOCKS5 server.
    async fn handshake(
        stream: &mut TcpStream,
        credentials: &Option<(&str, &str)>,
    ) -> Result<(), Socks5Error> {
        let greeting = if credentials.is_some() {
            vec![0x05, 0x02, 0x00, 0x02]
        } else {
            vec![0x05, 0x01, 0x00]
        };

        stream.write_all(&greeting).await?;

        // Read the handshake response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        match response[1] {
            0x00 => {} // No authentication needed
            0x02 => {
                if let Some(creds) = credentials {
                    Socks5Client::authenticate(stream, creds).await?;
                } else {
                    return Err(Socks5Error::AuthenticationFailed);
                }
            }
            _ => return Err(Socks5Error::HandshakeFailed),
        }

        Ok(())
    }

    /// Connect through the given SOCKS5 proxy to the given [`SocketAddr`].
    /// Optinally, provide credentials in the form of username and password.
    /// Returns a [`TcpStream`] on success and [`Socks5Error`] in case anything
    /// fails during the connection.
    pub async fn connect(
        proxy_addr: &str,
        target_addr: &SocketAddr,
        credentials: Option<(&str, &str)>,
    ) -> Result<TcpStream, Socks5Error> {
        let mut stream = TcpStream::connect(proxy_addr).await?;

        // Perform SOCKS5 handshake
        Socks5Client::handshake(&mut stream, &credentials).await?;

        // Build the request
        let mut request = vec![0x05, 0x01, 0x00];

        match target_addr.ip() {
            IpAddr::V4(ip) => {
                request.push(AddrType::IPv4.as_byte());
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(AddrType::IPv6.as_byte());
                request.extend_from_slice(&ip.octets());
            }
        }

        request.extend_from_slice(&target_addr.port().to_be_bytes());

        stream.write_all(&request).await?;

        let mut response = vec![0u8; 10];
        stream.read_exact(&mut response).await?;

        if response[1] != 0x00 {
            return Err(Socks5Error::ConnectionFailed);
        }

        Ok(stream)
    }

    /// Connect through the given SOCKS5 proxy to the given host and port.
    /// DNS resolution will be done on the SOCKS5 server-side.
    /// Optonally, provide credentials in the form of username and password.
    /// Returns a [`TcpStream`] on success and [`Socks5Error`] in case anything
    /// fails during the connection.
    pub async fn connect_with_domain(
        proxy_addr: &str,
        domain: &str,
        port: u16,
        credentials: Option<(&str, &str)>,
    ) -> Result<TcpStream, Socks5Error> {
        let mut stream = TcpStream::connect(proxy_addr).await?;

        // Perform SOCKS5 handshake
        Socks5Client::handshake(&mut stream, &credentials).await?;

        // Build the request
        let mut request = vec![
            0x05,
            0x01,
            0x00,
            AddrType::DomainName.as_byte(),
            domain.len().try_into().unwrap(),
        ];
        request.extend_from_slice(domain.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;

        let mut response = vec![0u8; 10];
        stream.read_exact(&mut response).await?;

        if response[1] != 0x00 {
            return Err(Socks5Error::ConnectionFailed);
        }

        Ok(stream)
    }
}
