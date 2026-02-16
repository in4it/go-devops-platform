package rest

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/in4it/go-devops-platform/logging"
	"github.com/in4it/go-devops-platform/storage"
	"golang.org/x/crypto/acme/autocert"
)

var (
	enableTLSWaiter    chan (bool) = make(chan bool)
	TLSWaiterCompleted bool
)

func StartServer(httpPort, httpsPort int, storage storage.Iface, c *Context, assets fs.FS) {
	go handleSignals(c)

	assetsFS, err := fs.Sub(assets, "static")
	if err != nil {
		log.Fatalf("could not load static web assets")
	}

	indexHtml, err := assetsFS.Open("index.html")
	if err != nil {
		log.Fatalf("could not load static web assets (index.html)")
	}
	indexHtmlBody, err := io.ReadAll(indexHtml)
	if err != nil {
		log.Fatalf("could not read static web assets (index.html)")
	}

	certManager := autocert.Manager{}

	// HTTP Configuration
	go func() { // start http server
		log.Printf("Start http server on port %d", httpPort)
		httpServer := &http.Server{
			Addr: fmt.Sprintf(":%d", httpPort),

			Handler: certManager.HTTPHandler(c.loggingMiddleware(c.httpsRedirectMiddleware(c.corsMiddleware(c.getRouter(assetsFS, indexHtmlBody))))),

			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,

			MaxHeaderBytes: 1 << 20, // 1MB
		}

		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	// TLS Configuration
	if !c.EnableTLS || !canEnableTLS(c.Hostname) {
		<-enableTLSWaiter
	}
	// only enable when TLS is enabled

	logging.DebugLog(fmt.Errorf("enabling TLS endpoint with let's encrypt for hostname '%s'", c.Hostname))
	certManager.Prompt = autocert.AcceptTOS
	certManager.HostPolicy = autocert.HostWhitelist(c.Hostname)
	certManager.Cache = autocert.DirCache("tls-certs")
	tlsServer := &http.Server{
		Addr: fmt.Sprintf(":%d", httpsPort),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
		Handler: c.loggingMiddleware(c.corsMiddleware(c.getRouter(assetsFS, indexHtmlBody))),

		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,

		MaxHeaderBytes: 1 << 20, // 1MB
	}
	c.Protocol = "https"
	TLSWaiterCompleted = true
	log.Fatal(tlsServer.ListenAndServeTLS("", ""))
}
