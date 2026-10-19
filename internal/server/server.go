package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	handler     http.Handler
	tlsCert     tls.Certificate
}

// New creates a server that serves handler over HTTP and over HTTPS using
// tlsCert (see LoadTLSCertificate).
func New(handler http.Handler, tlsCert tls.Certificate) *Server {
	return &Server{handler: handler, tlsCert: tlsCert}
}

func (s *Server) Start(httpAddr, httpsAddr string) error {
	s.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      s.handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.httpsServer = &http.Server{
		Addr:         httpsAddr,
		Handler:      s.handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{s.tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	errCh := make(chan error, 2)

	go func() {
		log.Printf("HTTP server listening on %s", httpAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	go func() {
		log.Printf("HTTPS server listening on %s", httpsAddr)
		if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("Received signal %s, shutting down", sig)
	case err := <-errCh:
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.httpServer.Shutdown(ctx)
	s.httpsServer.Shutdown(ctx)
	return nil
}
