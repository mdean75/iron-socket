use std::fs::File;
use std::io;
use std::io::{BufReader, Error};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use clap::Parser;
use ktls::CorkStream;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::certs;

fn main() {
    let args = Args::parse();
    println!("args: {:?}", args);

    let certs = load_certs(Path::new("new-certificate.pem")).map_err(|e| e.to_string())?;
    let ccerts = certs.into_iter().map(Certificate).collect();
    let key = load_keys_again(Path::new("new-privatekey.pem")).map_err(|e| e.to_string())?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(ccerts, key)
        .map_err(|e| e.to_string())?;

    config.enable_secret_extraction = true;

    let stream = unsafe { UnixStream::from_raw_fd(args.fd) };

    let client_stream = CorkStream::new(stream);
    println!("cork stream io as raw fd: {}", client_stream.io.as_raw_fd());


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
