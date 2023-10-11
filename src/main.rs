use std::collections::HashMap;
use std::env::consts::OS;
use std::fmt::format;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use axum::{Router, ServiceExt};
use axum::routing::get;
use nix::libc::{c_int, c_void, socklen_t};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Mutex;
use tokio::{select, task};

#[tokio::main]
async fn main() {
    println!("My pid is {}", process::id());
    run_listener("3000", "127.0.0.1", "192.168.40.4").await.unwrap();
}

async fn run_listener(port: &str, listener_ip: &str, backend_ip: &str) -> Result<String, String> {
     let cache: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    let monitor_cache = cache.clone();
    task::spawn(async move {
        let app = Router::new()
            .route("/cache", get(|| async move {

                let mut response = String::from("Current connections to server\n");
                let mon = monitor_cache.lock().await.clone().into_iter();
                for (k, v) in mon {
                    response.push_str(format!("{} -> {}\n", k, v).as_str())
                }
                response
            }));
        let s = Ipv4Addr::new(127, 0, 0, 1);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await.unwrap();
    });

    let listener = TcpListener::bind(format!("{listener_ip}:{port}"))
        .await.map_err(|e| e.to_string())?;

    loop {
        let (mut client_stream, addr) = listener.accept().await.map_err(|e| e.to_string())?;

        println!("Incoming connection from {}", addr);
        // let f = unsafe { File::from_raw_fd(client_stream.as_raw_fd()) };
        // println!("fd: {:?}", f.as_fd());

        let sock = TcpSocket::new_v4().unwrap();

        let dest_addr = client_stream.local_addr().unwrap();
        let orig_addr = client_stream.peer_addr().unwrap();


        // 	syscall.SetsockoptInt(sockFD, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
        let result = unsafe {
            let flag = 1;
            let flag_ptr = &flag as *const c_int as *const c_void;

            nix::libc::setsockopt(sock.as_raw_fd(), nix::libc::SOL_IP, nix::libc::IP_TRANSPARENT, flag_ptr, ::std::mem::size_of::<c_int>() as socklen_t)
        };

        println!("setsockopt result: {}", result);

        let bind_res = sock.bind(orig_addr).unwrap();
        // let connect = sock.connect(dest_addr).await.unwrap();


        // nix::sys::socket::bind(sock.as_raw_fd(), client_stream.peer_addr().unwrap())

        let server_port = port.clone().to_string();
        let backend_listener_ip = backend_ip.to_string();
        let proxy_listener_ip = listener_ip.to_string();
        let cache_manager = cache.clone();

        // TcpStream::connect()

        let conn_handle = tokio::spawn(async move {
            if let Ok(server_stream) = sock.connect(dest_addr).await {
            // if let Ok(server_stream) = TcpStream::connect(format!("{}:{}", backend_listener_ip, server_port)).await {

                let server_local_addr = server_stream.local_addr().unwrap().to_string();
                let server_peer_addr = server_stream.peer_addr().unwrap().to_string();

                {
                    let mut cache_guard = cache_manager.lock().await;
                    cache_guard.insert(server_local_addr.clone(), server_peer_addr);
                }


                let (mut client_read, mut client_write) = client_stream.into_split();
                let (mut server_read, mut server_write) = server_stream.into_split();

                let client_handle = tokio::spawn(async move {
                    tokio::io::copy(&mut client_read, &mut server_write).await
                });

                let server_handle = tokio::spawn(async move {
                    tokio::io::copy(&mut server_read, &mut client_write).await
                });

                select! {
                    _ = client_handle => println!("client disconnected"),
                    _ = server_handle => println!("server disconnected"),
                }

                {
                    let mut cache_guard = cache_manager.lock().await;
                    cache_guard.remove(server_local_addr.as_str());
                }
            }
        });
    }
}
