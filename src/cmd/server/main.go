// Command server runs the Loopable instance federation HTTP API (spec 60.3).
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"loopable.party/server/internal/objectstore"
	"loopable.party/server/internal/protocol/encoding"
	"loopable.party/server/internal/protocol/identifiers"
	"loopable.party/server/internal/protocol/instance"
	"loopable.party/server/internal/server"
	"loopable.party/server/internal/store"
)

func main() {
	listen := flag.String("listen", ":8449", "HTTP listen address")
	domain := flag.String("domain", "", "canonical hostname of this instance")
	documentPath := flag.String("document", "", "path to the signed instance document (ored CBOR map)")
	dsn := flag.String("dsn", "", "PostgreSQL DSN for the persistent store")
	dataDir := flag.String("data-dir", "", "directory for local media object storage")
	flag.Parse()

	if *domain == "" || *documentPath == "" || *dsn == "" || *dataDir == "" {
		log.Fatal("--domain, --document, --dsn, and --data-dir are required")
	}

	document, err := loadDocument(*documentPath)
	if err != nil {
		log.Fatalf("load instance document: %v", err)
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
