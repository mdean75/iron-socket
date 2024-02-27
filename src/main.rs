use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::{env, fs, process, vec};
use std::ffi::{c_char, CString};
use std::sync::Arc;
use axum::{Router, ServiceExt};
use axum::routing::get;
use clap::Parser;
use nix::libc;
use nix::libc::{execv};
use nix::sys::socket::SockaddrLike;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;
use tokio::{select, task};

#[derive(Serialize, Deserialize)]
struct ConnectionCache {
    cache: Vec<FdNamePair>
}

#[derive(Serialize, Deserialize)]
struct FdNamePair {
    fd: i32,
    name: String,
}

#[tokio::main]
async fn main() {
    let osargs = env::args().collect::<String>();
    println!("My pid is {} and i was started with {:?}", process::id(), osargs);
    let args = Args::parse();
    println!("{:?}", args);
    if args.restore {
        println!("restoring prior established connections");
        restore_connections("3000", "127.0.0.1", "192.168.40.6").await;
    }
    run_listener("3000", "127.0.0.1", "192.168.40.6").await.unwrap();
}

async fn restore_connections(port: &str, _listener_ip: &str, backend_ip: &str) {
    println!("restoring connections");
    let saved_conns = fs::read_to_string("connection-cache.json").unwrap();
    let connection_cache: ConnectionCache = serde_json::from_str(saved_conns.as_str()).unwrap();
    connection_cache.cache.iter().for_each(|x| unsafe {

        let std_stream = TcpStream::from_raw_fd(x.fd);
        let stream = TokioTcpStream::from_std(std_stream).unwrap();

        let pport = port.to_string();
        let bbackend_ip = backend_ip.to_string();

        task::spawn(async move {
            if let Ok(server_stream) = TokioTcpStream::connect(format!("{}:{}", bbackend_ip, pport)).await {
                let (mut client_read, mut client_write) = stream.into_split();
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
            }
        });
    });
}

async fn run_listener(port: &str, listener_ip: &str, backend_ip: &str) -> Result<String, String> {
    println!("starting listener");
    let cache: Arc<Mutex<HashMap<i32, (String, String)>>> = Arc::new(Mutex::new(HashMap::new()));

    // let listener_cache = cache.clone();
    let monitor_cache = Arc::clone(&cache);
    task::spawn(async move {
        let cache = Arc::clone(&monitor_cache);
        let app = Router::new()
            .route("/cache", get(|| async move {
                let cache = Arc::clone(&cache); //&monitor_cache.clone(); // Clone the Arc for shared access

                let mut response = String::from("Current connections to server\n");
                let guard = cache.lock().await; // Acquire the lock
                for (k, v) in guard.iter() { // Iterate over the HashMap while holding the lock
                    response.push_str(format!("{}: {} -> {}\n", k, v.0, v.1).as_str());
                }
                drop(guard); // Explicitly release the lock

                response
            }))
            .route("/upgrade", get(|| async move {
                println!("Starting upgrade process");
                let cache = Arc::clone(&monitor_cache);//cache.clone(); // Clone the Arc again for this handler
                let guard = cache.lock().await; // Acquire the lock
                let _c = guard.clone(); // Clone the HashMap's contents for printing
                // drop(guard); // Release the lock

                let mut list: Vec<FdNamePair> = Vec::new();
                for (k, v) in guard.clone().iter() {
                    let pair: FdNamePair = FdNamePair{fd: *k, name: format!("{} -> {}", v.0, v.1)};
                    // list.push((*k, format!("{} -> {}", v.0, v.1)))
                    list.push(pair)
                }
                drop(guard);
                let connection_cache: ConnectionCache = ConnectionCache{cache: list};
                println!("persisting current cache: \n{}", serde_json::to_string_pretty(&connection_cache).unwrap());
                let mut f = fs::File::create("connection-cache.json").unwrap();
                f.write_all(serde_json::to_string_pretty(&connection_cache).unwrap().as_bytes()).unwrap();

                // call exec
                // let command = Command::new("iron-socket").arg("-r").spawn();
                // let process = command.unwrap();
                let binary_path = CString::new("/Users/mdeangelo/projects/rust/iron-socket/target/debug/iron-socket").unwrap();


                unsafe {
                    // let arguments = vec![CString::new("-r").unwrap().as_ptr()].as_ptr();
                    // let c_args = arguments.iter().for_each(|x| x.as_ptr()).as_ptr();
                    // Create a CString from the string "-r"
                    let arg = CString::new("-r").expect("Failed to create CString");

                    // Create a Vec<*const c_char> with a single element
                    let c_array: Vec<*const c_char> = vec![binary_path.as_ptr(), arg.as_ptr()];

                    let exit_code = execv(binary_path.as_ptr(), c_array.as_ptr());
                    println!("exit status: {}", exit_code.to_string())
                }
                // println!("{:?}", c);
                "TODO: implement upgrade handler"
            }));

        let _s = Ipv4Addr::new(127, 0, 0, 1);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await.unwrap();
    });

    let listener = TcpListener::bind(format!("{listener_ip}:{port}"))
        .await.map_err(|e| e.to_string())?;

    loop {
        let (client_stream, addr) = listener.accept().await.map_err(|e| e.to_string())?;

        println!("Incoming connection from {}", addr);

        let _dest_addr = client_stream.local_addr().unwrap();
        let _orig_addr = client_stream.peer_addr().unwrap();



        let server_port = port.to_string();
        let backend_listener_ip = backend_ip.to_string();
        let _proxy_listener_ip = listener_ip.to_string();
        let cache_manager = cache.clone();

        // TcpStream::connect()

        let new_flags = !libc::FD_CLOEXEC;
        let result = unsafe { libc::fcntl(client_stream.as_raw_fd(), libc::F_SETFD, new_flags) };
        if result == -1 {
            // Handle error, e.g., using std::io::Error::last_os_error()
            println!("Error clearing close on exec flag: {}", std::io::Error::last_os_error());
        } else {
            println!("Close on exec flag cleared successfully");
        }
        // client_stream.as_raw_fd().
        let _conn_handle = tokio::spawn(async move {
            // if let Ok(server_stream) = sock.connect(dest_addr).await {
            if let Ok(server_stream) = TokioTcpStream::connect(format!("{}:{}", backend_listener_ip, server_port)).await {

                let cache_fd = client_stream.as_raw_fd();
                let server_local_addr = client_stream.local_addr().unwrap();//.to_string();
                let server_peer_addr = client_stream.peer_addr().unwrap();//to_string();

                {
                    let mut cache_guard = cache_manager.lock().await;
                    cache_guard.insert(cache_fd.as_raw_fd(), (server_local_addr.clone().to_string(), server_peer_addr.to_string()));
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
                    cache_guard.remove(&cache_fd.as_raw_fd());
                }
            }
        });
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    restore: bool,
}
