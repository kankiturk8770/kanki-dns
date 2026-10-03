//! Generic HTTP(S) accept loop (HTTP/1.1 + HTTP/2) that feeds an axum Router
//! and injects the peer address as `ConnectInfo`.
use axum::{extract::ConnectInfo, Router};
use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::TlsAcceptor;
use tower_service::Service;

pub async fn serve_http(listener: TcpListener, acceptor: Option<TlsAcceptor>, app: Router) -> anyhow::Result<()> {
    let limit = Arc::new(Semaphore::new(2048));
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
        let app = app.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                let mut app = app.clone();
                async move { app.call(req).await }
            });
            let builder = Builder::new(TokioExecutor::new());
            match acceptor {
                Some(a) => {
                    let Ok(Ok(tls)) = timeout(Duration::from_secs(10), a.accept(tcp)).await else { return };
                    let _ = builder.serve_connection(TokioIo::new(tls), svc).await;
                }
                None => {
                    let _ = builder.serve_connection(TokioIo::new(tcp), svc).await;
                }
            }
        });
    }
}
