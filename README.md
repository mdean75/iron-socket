# Iron Socket
> A transparent tcp proxy for tls connections with seamless self upgrade. 

Accept tls tcp connections and transparently proxy to a backend service. 
Supports in place self upgrades using exec without interruption to established tls sockets by using kernel tls offload (ktls).
Requires OS and kernel version compatible with ktls.


## Built with
<img src="https://img.shields.io/badge/Rust-FFF?style=for-the-badge&logo=rust&logoColor=black" /> 

## How does this work

While it is relatively easy to restore plain text tcp connections after calling exec, with tls connections the tls handshake information is typically lost during the upgrade and restore process. 
This results in the application receiving encrypted data from the socket and no way to decrypt it.

The solution is to use ktls to offload the encrypt and decrypt operations to the kernel. This allows the application to then handle plain text data. 
Which in turn allows the upgrade using exec to restore the socket and continue processing data without the need to worry about restoring tls handshake information.

## Process / steps involved

1. The application accepts incoming tcp connections
2. Tls termination is performed by the application
3. Extract tls handshake secrets and provide to kernel
4. Kernel now handles all encrypt/decrypt ops and application deals with plain text data

## Kernel TLS

>Linux kernel provides TLS connection offload infrastructure. Once a TCP connection is in ESTABLISHED state user space can enable the TLS Upper Layer Protocol (ULP) and install the cryptographic connection state.

There are documented performance increases when using kernel tls offload, however for this use case the biggest benefit is being able to reconnect to a tls socket without the need to worry about encryption at the application level.

For more information about ktls

https://www.kernel.org/doc/html/latest/networking/tls-offload.html
https://www.kernel.org/doc/html/latest/networking/tls.html#kernel-tls
https://netdevconf.info/0x14/pub/papers/25/0x14-paper25-talk-paper.pdf
https://netdevconf.info/1.2/papers/ktls.pdf

### ktls can operate in three modes:

        Software crypto mode (TLS_SW) - CPU handles the cryptography. In most basic cases only crypto operations synchronous with the CPU can be used, but depending on calling context CPU may utilize asynchronous crypto accelerators. The use of accelerators introduces extra latency on socket reads (decryption only starts when a read syscall is made) and additional I/O load on the system.

        Packet-based NIC offload mode (TLS_HW) - the NIC handles crypto on a packet by packet basis, provided the packets arrive in order. This mode integrates best with the kernel stack and is described in detail in the remaining part of this document (ethtool flags tls-hw-tx-offload and tls-hw-rx-offload).

        Full TCP NIC offload mode (TLS_HW_RECORD) - mode of operation where NIC driver and firmware replace the kernel networking stack with its own TCP handling, it is not usable in production environments making use of the Linux networking stack for example any firewalling abilities or QoS and packet scheduling (ethtool flag tls-hw-record).
The operation mode is selected automatically based on device configuration, offload opt-in or opt-out on per-connection basis is not currently supported.

### ktls statistics

/proc/net/tls_stat



    TlsCurrTxSw, TlsCurrRxSw - number of TX and RX sessions currently installed where host handles cryptography

    TlsCurrTxDevice, TlsCurrRxDevice - number of TX and RX sessions currently installed where NIC handles cryptography

    TlsTxSw, TlsRxSw - number of TX and RX sessions opened with host cryptography

    TlsTxDevice, TlsRxDevice - number of TX and RX sessions opened with NIC cryptography

    TlsDecryptError - record decryption failed (e.g. due to incorrect authentication tag)

    TlsDeviceRxResync - number of RX resyncs sent to NICs handling cryptography

    TlsDecryptRetry - number of RX records which had to be re-decrypted due to TLS_RX_EXPECT_NO_PAD mis-prediction. Note that this counter will also increment for non-data records.

    TlsRxNoPadViolation - number of data RX records which had to be re-decrypted due to TLS_RX_EXPECT_NO_PAD mis-prediction.

From TLS performance characterization on modern x86 CPUs by
Pawel Szymanski, Manasi Deval (Intel)

https://netdevconf.info/0x14/pub/papers/25/0x14-paper25-talk-paper.pdf
>KTLS module supports two cipher
options: AES_GCM_128 and AES_GCM_256.
In the simplest case when an application wants to send
data via TLS connection, it passes the data to a TLS library.
Next the library invokes write() system call to send the data
into the TLS module. When the cryptographic module is
about to encrypt the data, it reads the plain text data from
buffers located in user space and puts the cipher text into
buffers located in Kernel space

From KTLS: Linux Kernel Transport Layer Security by Dave Watson (Facebook)
https://netdevconf.info/1.2/papers/ktls.pdf
>In this scheme, the TLS library is used to handle the con-
trol messages and do the handshake, and does not need to
be modified. It can maintain control of the original TCP fd,
while unencrypted data flows through the KTLS socket. The
user space application only needs to handle application data,
and use standard socket system calls.

## Language Support

## C
Most reference examples are provided in C and implemented by extracting handshake crypto information and setting socket options.

## Rust 
Kernel tls offload is accomplished in Rust using rustls and ktls crates. 
First the server rustls configuration is modified to enable tls secret extraction.
Incoming tcp connections are wrapped in a CorkStream from ktls crate. 
The CorkStream is then used for the tls handshake.
Once the tls handshake is completed, ktls is configured for the socket using ktls::config_ktls_server for the tls stream.
This Rust solution requires no low-level setting of socket options.

*note: The ktls crate also utilizes rustls and the ktls crate version and local project version must use compatible versions. 
This requirement results in unable to use the most current version of rustls.

### Unsupported Language
## Go
Go does not expose all the necessary information required to enable ktls. 
There is a proposal from 2021 to add support to the language, however is still outstanding.
https://github.com/golang/go/issues/44506
