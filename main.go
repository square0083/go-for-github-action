package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go-for-action/hello"
	"go-for-action/internal/user"
)

func main() {
	count := flag.Int("count", 1, "number of times to print the greeting")
	flag.Parse()

	for i := 0; i < *count; i++ {
		fmt.Println(hello.Greet())
	}

	store, err := user.NewSQLiteStore(envOr("DATABASE_PATH", "data/app.db"))
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	defer store.Close()

	secret := envOr("JWT_SECRET", "dev-only-change-me")
	tm, err := user.NewTokenManager(secret, time.Duration(envIntOr("JWT_TTL_HOURS", 24))*time.Hour)
	if err != nil {
		log.Fatalf("init token manager: %v", err)
	}

	svc := user.NewService(store, tm)
	handler := user.NewHandler(svc)

	mux := http.NewServeMux()
	handler.Register(mux)

	addr := envOr("HTTP_ADDR", ":8080")
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}
