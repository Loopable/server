// Command server runs the Loopable instance federation HTTP API (spec 60.3).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/instance"
	"loopable.party/server/internal/server"
	"loopable.party/server/internal/store"
)

// stringList accumulates a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	listen := flag.String("listen", ":8449", "HTTP listen address")
	domain := flag.String("domain", "", "canonical hostname of this instance")
	documentPath := flag.String("document", "", "path to the signed instance document (ored CBOR map)")
	dsn := flag.String("dsn", "", "PostgreSQL DSN for the persistent store")
	dataDir := flag.String("data-dir", "", "directory for local media object storage")
	opKey := flag.String("op-key", "", "PKCS#8 PEM path of this instance's operational private key (federation signing)")
	var peerPaths stringList
	flag.Var(&peerPaths, "peer", "path to a signed peer instance document (repeatable)")
	syncIntervalSeconds := flag.Int("sync-interval", 30, "federation sync interval in seconds")
	federationScheme := flag.String("federation-scheme", "https", "scheme for outbound federation requests (https or http)")
	federationPort := flag.String("federation-port", "", "non-default port for outbound federation requests")
	flag.Parse()

	if *domain == "" || *documentPath == "" || *dsn == "" || *dataDir == "" {
		log.Fatal("--domain, --document, --dsn, and --data-dir are required")
	}
	if len(peerPaths) > 0 && *opKey == "" {
		log.Fatal("--peer requires --op-key so outbound sync can be authenticated")
	}

	document, err := loadDocument(*documentPath)
	if err != nil {
		log.Fatalf("load instance document: %v", err)
	}

	var signingKey ed25519.PrivateKey
	if *opKey != "" {
		signingKey, err = loadOperatorKey(*opKey)
		if err != nil {
			log.Fatalf("load operational signing key: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, store.Config{DSN: *dsn})
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		log.Fatalf("migrate store: %v", err)
	}

	blobs, err := objectstore.NewLocal(*dataDir)
	if err != nil {
		log.Fatalf("open media store: %v", err)
	}

	adapter := server.NewStoreAdapter(db)
	peerDocuments := server.NewPeerRegistry()
	for _, path := range peerPaths {
		peer, err := loadDocument(path)
		if err != nil {
			log.Fatalf("load peer document %s: %v", path, err)
		}
		if err := db.PutPeerDocument(ctx, peer.InstanceID, peer); err != nil {
			log.Fatalf("store peer document %s: %v", path, err)
		}
		if err := peerDocuments.Register(peer); err != nil {
			log.Fatalf("register peer document %s: %v", path, err)
		}
	}
	handler, err := server.New(server.Config{
		Domain:     *domain,
		Document:   document,
		Events:     adapter,
		Objects:    adapter,
		Blobs:      blobs,
		Devices:    adapter,
		Membership: adapter,
		Peers:      peerDocuments,
	})
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

	var reconciler *server.Reconciler
	if signingKey != nil {
		reconciler, err = server.NewReconciler(handler, server.ReconcilerOptions{
			SigningKey: signingKey,
			Peers:      db,
			Interval:   time.Duration(*syncIntervalSeconds) * time.Second,
			Scheme:     *federationScheme,
			Port:       *federationPort,
		})
		if err != nil {
			log.Fatalf("build reconciler: %v", err)
		}
		if err := reconciler.RestorePeers(ctx); err != nil {
			log.Fatalf("restore peer documents: %v", err)
		}
		go reconciler.Run(ctx)
	}

	instanceText, err := identifiers.String(identifiers.InstanceID, document.InstanceID)
	if err != nil {
		log.Fatalf("format instance ID: %v", err)
	}

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           handler.Handler(),
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		log.Printf("instance %s serving on %s for %s", instanceText, *listen, *domain)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func loadDocument(path string) (*instance.Document, error) {
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values any
	if err := encoding.Decode(wire, &values); err != nil {
		return nil, err
	}
	document, err := instance.Parse(values)
	if err != nil {
		return nil, err
	}
	return &document, nil
}

// loadOperatorKey reads a PKCS#8-encoded PEM Ed25519 private key.
func loadOperatorKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in the signing key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	signing, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not an Ed25519 key")
	}
	return signing, nil
}
