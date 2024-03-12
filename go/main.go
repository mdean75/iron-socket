package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// todo: can we make a tiny rust bin that takes in an int for an fd, performs a tls handshake and offloads tls to kernel
// then returns 0 for success or non-zero for failure.
// failure codes can include tls mod not enabled, or any other error encountered during handshake
var cache map[string]uintptr = make(map[string]uintptr)

func main() {
	fmt.Println(os.Args)
	restore := flag.Bool("r", false, "upgrade")
	flag.Parse()

	fmt.Println("pid:", os.Getpid())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for {

			s := <-sig
			switch s {
			case syscall.SIGUSR1:
				fmt.Println("received USR1, initiating upgrade")
				upgrade()

			case syscall.SIGUSR2:
				fmt.Println("received USR2, get info")
				info()
			}
		}
	}()
	runTLS(*restore)
}

func info() {
	fmt.Println("established connections:", cache)
}

func upgrade() {
	fmt.Println("upgrading to new version\nsaving connection cache to disk")
	f, err := os.Create("connections.gob")
	if err != nil {
		fmt.Println("error opening file to save connection cache")
		return
	}
	defer f.Close()
	err = gob.NewEncoder(f).Encode(cache)
	if err != nil {
		fmt.Println("unable to save cache to disk:", err)
		return
	}

	syscall.Exec("go-sock", []string{"go-sock", "-r"}, []string{})
}

func runTLS(restore bool) {
	fmt.Println("starting tls listener")
	cert, err := tls.LoadX509KeyPair("server-bundle.crt", "server.key")
	if err != nil {
		// Handle error
		fmt.Println("load key pair:", err)
		return
	}

	clientCertPool := x509.NewCertPool()
	pem, err := os.ReadFile("ca-bundle.crt")
	if err != nil {
		fmt.Println(err)
		return
	}
	f, err := os.Create("keylog.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()
	clientCertPool.AppendCertsFromPEM(pem)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  clientCertPool,
	}

	fmt.Println("restore:", restore)
	if restore {
		fmt.Println("restoring saved connections")
		f, err := os.Open("connections.gob")
		if err != nil {
			fmt.Println(err)
			return
		}
		var m map[string]uintptr

		fmt.Println("decode connections")
		err = gob.NewDecoder(f).Decode(&m)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("restored connection map:", m)

		// reconnect and process
		for name, fd := range m {
			go func(name string, fd uintptr) {
				newFile := os.NewFile(uintptr(fd), f.Name())
				fileconn, err := net.FileConn(newFile)
				if err != nil {
					fmt.Println(err)
					return
				}

				defer func() {
					//newFile.Close()
					//fileconn.Close()
					//newtlsconn.Close()
				}()

				buf := make([]byte, 1024)
				for {
					_, err := fileconn.Read(buf)
					if err != nil {
						fmt.Println("tls read:", err)
						return
					}
					fmt.Println("received msg:", string(buf))
				}
			}(name, fd)
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:3001")
	if err != nil {
		// Handle error
		fmt.Println("listen tcp:", err)
	}

	lis := tls.NewListener(listener, config)

	for {
		conn, err := lis.Accept()
		if err != nil {
			fmt.Println("tls accept:", err)
			return
		}

		go func(c net.Conn) {
			tlsConn := c.(*tls.Conn)

			//if err := tlsConn.Handshake(); err != nil {
			//	fmt.Println("handshake failure:", err)
			//	return
			//}
			//peerCert := tlsConn.ConnectionState().PeerCertificates
			//if peerCert[0].Subject.CommonName != "" {
			//	fmt.Println("common name does not match, rejecting connection:", peerCert[0].Subject.CommonName)
			//	tlsConn.Close()
			//	return
			//}

			tlsNetConn := tlsConn.NetConn()
			tcpConn := tlsNetConn.(*net.TCPConn)

			fmt.Println(tcpConn.LocalAddr())
			f, err := tcpConn.File()
			if err != nil {
				fmt.Println(err)
				return
			}
			fd, err := syscall.Dup(int(f.Fd()))
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(f.Name())
			newFile := os.NewFile(uintptr(fd), f.Name())
			fileconn, err := net.FileConn(newFile)
			if err != nil {
				fmt.Println(err)
				return
			}

			// ******************************
			// instead of performing the tls handshake here, pass fd to Rust subprocess to perform handshake and offload to ktls
			// ******************************
			newtlsconn := tls.Server(fileconn, config)
			buf := make([]byte, 1024)

			// make handshake and check multi cid validation
			if err := newtlsconn.Handshake(); err != nil {
				fmt.Println("handshake failure:", err)
				return
			}

			// ******************************

			cache[newFile.Name()] = newFile.Fd()
			defer func() {
				delete(cache, newFile.Name())
				//newFile.Close()
				//fileconn.Close()
			}()
			//fmt.Printf("conn state: %+v\n", newtlsconn.ConnectionState())

			//tlsState := newtlsconn.ConnectionState()
			//label := "my-exported-key"
			//context := []byte("export-context")
			//keyingMaterial, err := tlsState.ExportKeyingMaterial(label, context, 32)
			//if err != nil {
			//	fmt.Println(err)
			//}
			//// Print the exported keying material
			//fmt.Printf("Exported Keying Material: %x\n", keyingMaterial)
			for {
				_, err := newtlsconn.Read(buf)
				if err != nil {
					fmt.Println("tls read:", err)
					return
				}
				fmt.Println("received msg:", string(buf))
			}
		}(conn)
	}
}
