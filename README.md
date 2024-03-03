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

There are documented performance increases when using kernel tls offload, however for this use case the biggest benefit is being able to reconnect to a tls socket without the need to worry about encryption at the application level.

Can be configured to use host cpu or nic.

For more information about ktls

https://www.kernel.org/doc/html/latest/networking/tls-offload.html
https://www.kernel.org/doc/html/latest/networking/tls.html#kernel-tls

ktls statistics

/proc/net/tls_stat



    TlsCurrTxSw, TlsCurrRxSw - number of TX and RX sessions currently installed where host handles cryptography

    TlsCurrTxDevice, TlsCurrRxDevice - number of TX and RX sessions currently installed where NIC handles cryptography

    TlsTxSw, TlsRxSw - number of TX and RX sessions opened with host cryptography

    TlsTxDevice, TlsRxDevice - number of TX and RX sessions opened with NIC cryptography

    TlsDecryptError - record decryption failed (e.g. due to incorrect authentication tag)

    TlsDeviceRxResync - number of RX resyncs sent to NICs handling cryptography

    TlsDecryptRetry - number of RX records which had to be re-decrypted due to TLS_RX_EXPECT_NO_PAD mis-prediction. Note that this counter will also increment for non-data records.

    TlsRxNoPadViolation - number of data RX records which had to be re-decrypted due to TLS_RX_EXPECT_NO_PAD mis-prediction.

