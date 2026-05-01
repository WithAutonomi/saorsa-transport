// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper, UdpPoller};
use crate::Instant;

/// Tokio runtime implementation
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(TokioTimer(Box::pin(sleep_until(i.into()))))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        // `quinn_udp::UdpSocketState::new` configures the socket (non-blocking,
        // GRO, IP_PMTUDISC_PROBE, IPV6_RECVPKTINFO, etc.); we must call it
        // before handing the std socket to tokio.
        let inner = quinn_udp::UdpSocketState::new((&sock).into())?;
        Ok(Arc::new(UdpSocket {
            io: tokio::net::UdpSocket::from_std(sock)?,
            inner,
        }))
    }

    fn now(&self) -> Instant {
        Instant::from(tokio::time::Instant::now())
    }
}

/// Tokio timer implementation
#[derive(Debug)]
struct TokioTimer(Pin<Box<Sleep>>);

impl AsyncTimer for TokioTimer {
    fn reset(mut self: Pin<&mut Self>, i: Instant) {
        self.0.as_mut().reset(i.into())
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        self.0.as_mut().poll(cx).map(|_| ())
    }
}

/// Tokio UDP socket implementation backed by `quinn_udp::UdpSocketState`.
///
/// The socket performs batched I/O: `recvmmsg` (with GRO coalescing on Linux)
/// on receive and `sendmmsg` (with GSO segmentation) on send. This is the path
/// that lets a single relay endpoint absorb thousands of packets per second
/// without the kernel UDP receive buffer overflowing on every burst.
#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: quinn_udp::UdpSocketState,
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

/// Extension trait to convert tokio::Handle to Runtime
#[allow(dead_code)]
pub(super) trait HandleRuntime {
    /// Create a Runtime implementation from this handle
    fn as_runtime(&self) -> TokioRuntime;
}

impl HandleRuntime for tokio::runtime::Handle {
    fn as_runtime(&self) -> TokioRuntime {
        TokioRuntime
    }
}
