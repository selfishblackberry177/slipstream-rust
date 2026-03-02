use crate::error::ClientError;
use slipstream_core::net::{bind_udp_socket_addr, is_transient_udp_error};
use std::cell::Cell;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::mpsc;

pub(crate) struct RecvDatagram {
    pub(crate) data: Vec<u8>,
    pub(crate) peer: SocketAddr,
}

/// Error returned by `DnsTransport::recv_from`.
pub(crate) enum TransportRecvError {
    Io(std::io::Error),
    ChannelClosed,
}

/// Error returned by `DnsTransport::try_recv_from`.
pub(crate) enum TryRecvError {
    WouldBlock,
    Io(std::io::Error),
    Closed,
}

/// Abstracts over a pool of UDP sockets with random source-port selection.
///
/// All sockets are IPv6 dual-stack (`[::]:0`). Outgoing queries pick a socket
/// at random. Incoming responses are aggregated from all sockets via per-socket
/// receive tasks that forward into a shared channel.
///
/// A pool of 1 socket (the default) naturally degenerates to single-port
/// behavior with no special-casing needed.
pub(crate) struct DnsTransport {
    sockets: Vec<Arc<TokioUdpSocket>>,
    rng_state: Cell<u32>,
    recv_rx: mpsc::UnboundedReceiver<RecvDatagram>,
    canonical_local_addr: SocketAddr,
}

impl DnsTransport {
    pub(crate) async fn new(count: u16) -> Result<Self, ClientError> {
        let count = count.max(1) as usize;
        let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let sock = bind_udp_socket_addr(bind_addr, "UDP socket")
                .map_err(|e| ClientError::new(e.to_string()))?;
            sockets.push(Arc::new(sock));
        }
        let canonical_local_addr = sockets[0]
            .local_addr()
            .map_err(|e| ClientError::new(e.to_string()))?;

        let (tx, recv_rx) = mpsc::unbounded_channel();
        for sock in &sockets {
            let sock = Arc::clone(sock);
            let tx = tx.clone();
            tokio::spawn(recv_loop(sock, tx));
        }
        // Drop the original sender so the channel closes when all tasks exit.
        drop(tx);

        // Seed the xorshift RNG from the canonical port to get some initial entropy.
        let seed = canonical_local_addr.port() as u32;
        let rng_state = Cell::new(if seed == 0 { 0xDEAD_BEEF } else { seed });

        if count > 1 {
            tracing::info!("Random source port pool: {} sockets", count);
        }

        Ok(Self {
            sockets,
            rng_state,
            recv_rx,
            canonical_local_addr,
        })
    }

    /// Returns the local address of the first (canonical) socket. This is used
    /// for picoquic path identity — all sockets share the same local IP, only
    /// the ephemeral port differs. Using a consistent address avoids confusing
    /// picoquic's path tracking.
    pub(crate) fn canonical_local_addr(&self) -> SocketAddr {
        self.canonical_local_addr
    }

    /// Send a datagram to `dest`, picking a socket at random from the pool.
    /// In single-socket mode this is a direct send with no randomization.
    pub(crate) async fn send_to(
        &self,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Result<usize, std::io::Error> {
        let idx = if self.sockets.len() == 1 {
            0
        } else {
            self.random_index()
        };
        self.sockets[idx].send_to(buf, dest).await
    }

    /// Receive the next datagram from the aggregation channel.
    pub(crate) async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr), TransportRecvError> {
        match self.recv_rx.recv().await {
            Some(d) => {
                let len = d.data.len().min(buf.len());
                buf[..len].copy_from_slice(&d.data[..len]);
                Ok((len, d.peer))
            }
            None => Err(TransportRecvError::ChannelClosed),
        }
    }

    /// Non-blocking receive from the aggregation channel.
    pub(crate) fn try_recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr), TryRecvError> {
        match self.recv_rx.try_recv() {
            Ok(d) => {
                let len = d.data.len().min(buf.len());
                buf[..len].copy_from_slice(&d.data[..len]);
                Ok((len, d.peer))
            }
            Err(mpsc::error::TryRecvError::Empty) => Err(TryRecvError::WouldBlock),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TryRecvError::Closed),
        }
    }

    /// Simple xorshift32 to pick a random socket index. No external dependency.
    fn random_index(&self) -> usize {
        let mut s = self.rng_state.get();
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        self.rng_state.set(s);
        (s as usize) % self.sockets.len()
    }
}

async fn recv_loop(sock: Arc<TokioUdpSocket>, tx: mpsc::UnboundedSender<RecvDatagram>) {
    let mut buf = vec![0u8; 4096];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((size, peer)) => {
                let datagram = RecvDatagram {
                    data: buf[..size].to_vec(),
                    peer,
                };
                if tx.send(datagram).is_err() {
                    break;
                }
            }
            Err(err) if is_transient_udp_error(&err) => continue,
            Err(err) => {
                tracing::error!("recv_loop fatal error: {}", err);
                break;
            }
        }
    }
}
