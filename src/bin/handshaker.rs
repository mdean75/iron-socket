use clap::Parser;
use ktls::CorkStream;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::certs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Error};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("args: {:?}", args);

    let certs = load_certs(Path::new("../new-certificate.pem"))
        .map_err(|e| e.to_string())
        .unwrap();
    let ccerts = certs.into_iter().map(Certificate).collect();
    let key = load_keys_again(Path::new("../new-privatekey.pem"))
        .map_err(|e| e.to_string())
        .unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(ccerts, key)
        .map_err(|e| e.to_string())
        .unwrap();

    config.enable_secret_extraction = true;

    let stream = unsafe {
        let std_stream = std::net::TcpStream::from_raw_fd(args.fd);
        TokioTcpStream::from_std(std_stream).unwrap()
    };


    let client_stream = CorkStream::new(stream);
    println!("cork stream io as raw fd: {}", client_stream.io.as_raw_fd());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let accepted_stream = acceptor.accept(client_stream).await.unwrap();
    println!("protocol: {}, cipher: {}", accepted_stream.get_ref().1.protocol_version().unwrap().as_str().unwrap(), accepted_stream.get_ref().1.negotiated_cipher_suite().unwrap().suite().as_str().unwrap());
    ktls::config_ktls_server(accepted_stream).await.unwrap();

}

fn load_certs(path: &Path) -> Result<Vec<Vec<u8>>, Error> {
    certs(&mut BufReader::new(File::open(path)?))
}

fn load_keys_again(path: &Path) -> io::Result<PrivateKey> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

    Ok(PrivateKey(keys.remove(0)))
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    fd: i32,
}
