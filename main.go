package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

type Config struct {
	ListenAddr      string
	TLSEnabled      bool
	TLSCertFile     string
	TLSKeyFile      string
	MaxMessageSize  int
	MessageBuffer   int
	MaxClients      int
	RateLimit       int
	RateLimitWindow time.Duration
	IdleTimeout     time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:      "127.0.0.1:8000",
		TLSEnabled:      false,
		MaxMessageSize:  4096,
		MessageBuffer:   100,
		MaxClients:      100,
		RateLimit:       10,
		RateLimitWindow: time.Minute,
		IdleTimeout:     15 * time.Minute,
	}
}

type MessageType string

const (
	MessageTypeChat   MessageType = "chat"
	MessageTypeSystem MessageType = "system"
	MessageTypeError  MessageType = "error"
	MessageTypeAuth   MessageType = "auth"
)

type Message struct {
	ID        string      `json:"id"`
	Type      MessageType `json:"type"`
	From      string      `json:"from"`
	Content   string      `json:"content"`
	Timestamp time.Time   `json:"timestamp"`
}

type Client struct {
	ID         string
	conn       net.Conn
	outbound   chan *Message
	server     *Server
	lastActive time.Time
	mu         sync.RWMutex
}

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	requests, exists := rl.requests[clientID]
	if !exists {
		rl.requests[clientID] = []time.Time{now}
		return true
	}

	validRequests := make([]time.Time, 0, len(requests))
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= rl.limit {
		rl.requests[clientID] = validRequests
		return false
	}

	validRequests = append(validRequests, now)
	rl.requests[clientID] = validRequests
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-rl.window)

		for clientID, requests := range rl.requests {
			hasRecent := false
			for _, t := range requests {
				if t.After(windowStart) {
					hasRecent = true
					break
				}
			}
			if !hasRecent {
				delete(rl.requests, clientID)
			}
		}
		rl.mu.Unlock()
	}
}

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
}

func validateMessage(content string, maxSize int) error {
	if len(content) == 0 {
		return ValidationError{Field: "content", Message: "message cannot be empty"}
	}

	if len(content) > maxSize {
		return ValidationError{
			Field:   "content",
			Message: fmt.Sprintf("message exceeds maximum size of %d bytes", maxSize),
		}
	}

	if !utf8.ValidString(content) {
		return ValidationError{Field: "content", Message: "message contains invalid UTF-8"}
	}

	for _, r := range content {
		if r < 32 && r != '\n' && r != '\t' && r != '\r' {
			return ValidationError{Field: "content", Message: "message contains invalid control characters"}
		}
	}

	return nil
}

type Server struct {
	config      *Config
	listener    net.Listener
	clients     map[string]*Client
	clientsMu   sync.RWMutex
	entering    chan *Client
	leaving     chan *Client
	messages    chan *Message
	rateLimiter *RateLimiter
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	clientCount int32
}

func NewServer(config *Config) *Server {
	return &Server{
		config:      config,
		clients:     make(map[string]*Client),
		entering:    make(chan *Client),
		leaving:     make(chan *Client),
		messages:    make(chan *Message, config.MessageBuffer),
		rateLimiter: NewRateLimiter(config.RateLimit, config.RateLimitWindow),
	}
}

func (s *Server) Start(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	var err error
	if s.config.TLSEnabled {
		log.Printf("Starting secure chat server with TLS on %s", s.config.ListenAddr)

		cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificates: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		}

		s.listener, _ = tls.Listen("tcp", s.config.ListenAddr, tlsConfig)
	} else {
		log.Printf("Starting chat server (non-TLS) on %s", s.config.ListenAddr)
		s.listener, err = net.Listen("tcp", s.config.ListenAddr)
	}

	if err != nil {
		return fmt.Errorf("could not start listener: %w", err)
	}

	log.Printf("Server listening on %s (TLS: %v)", s.listener.Addr(), s.config.TLSEnabled)

	s.wg.Add(1)
	go s.broadcaster()

	s.wg.Add(1)
	go s.idleChecker()

	s.wg.Add(1)
	go s.acceptConnections()

	<-ctx.Done()
	log.Println("Shutdown signal received...")

	s.listener.Close()
	s.cancel()
	s.wg.Wait()

	log.Println("Server shut down gracefully")
	return nil
}

func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		currentCount := atomic.LoadInt32(&s.clientCount)
		if currentCount >= int32(s.config.MaxClients) {
			log.Printf("Max clients reached, rejecting connection from %s", conn.RemoteAddr())
			conn.Write([]byte("ERROR: Server full\n"))
			conn.Close()
			continue
		}

		atomic.AddInt32(&s.clientCount, 1)
		s.wg.Add(1)
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer atomic.AddInt32(&s.clientCount, -1)

	clientID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())

	client := &Client{
		ID:         clientID,
		conn:       conn,
		outbound:   make(chan *Message, s.config.MessageBuffer),
		server:     s,
		lastActive: time.Now(),
	}

	s.wg.Add(1)
	go client.writer()

	welcomeMsg := &Message{
		ID:        generateMessageID(),
		Type:      MessageTypeSystem,
		From:      "server",
		Content:   fmt.Sprintf("Welcome! You are connected securely. Your ID: %s", clientID),
		Timestamp: time.Now(),
	}
	client.outbound <- welcomeMsg

	s.messages <- &Message{
		ID:        generateMessageID(),
		Type:      MessageTypeSystem,
		From:      "server",
		Content:   fmt.Sprintf("User %s has joined", clientID),
		Timestamp: time.Now(),
	}

	s.entering <- client

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, s.config.MaxMessageSize), s.config.MaxMessageSize)

	for scanner.Scan() {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		client.updateActivity()

		if !s.rateLimiter.Allow(clientID) {
			errorMsg := &Message{
				ID:        generateMessageID(),
				Type:      MessageTypeError,
				From:      "server",
				Content:   "Rate limit exceeded. Please slow down.",
				Timestamp: time.Now(),
			}
			client.outbound <- errorMsg
			continue
		}

		content := scanner.Text()
		if err := validateMessage(content, s.config.MaxMessageSize); err != nil {
			errorMsg := &Message{
				ID:        generateMessageID(),
				Type:      MessageTypeError,
				From:      "server",
				Content:   fmt.Sprintf("Invalid message: %v", err),
				Timestamp: time.Now(),
			}
			client.outbound <- errorMsg
			continue
		}

		msg := &Message{
			ID:        generateMessageID(),
			Type:      MessageTypeChat,
			From:      clientID,
			Content:   content,
			Timestamp: time.Now(),
		}
		s.messages <- msg
	}

	s.leaving <- client
	s.messages <- &Message{
		ID:        generateMessageID(),
		Type:      MessageTypeSystem,
		From:      "server",
		Content:   fmt.Sprintf("User %s has left", clientID),
		Timestamp: time.Now(),
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error for client %s: %v", clientID, err)
	}
}

func (c *Client) writer() {
	defer c.server.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	encoder := json.NewEncoder(c.conn)

	for {
		select {
		case <-c.server.ctx.Done():
			return

		case msg, ok := <-c.outbound:
			if !ok {
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := encoder.Encode(msg); err != nil {
				log.Printf("Error writing to client %s: %v", c.ID, err)
				return
			}

		case <-ticker.C:
			pingMsg := &Message{
				ID:        generateMessageID(),
				Type:      MessageTypeSystem,
				From:      "server",
				Content:   "ping",
				Timestamp: time.Now(),
			}

			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := encoder.Encode(pingMsg); err != nil {
				log.Printf("Ping failed for client %s: %v", c.ID, err)
				return
			}
		}
	}
}

func (c *Client) updateActivity() {
	c.mu.Lock()
	c.lastActive = time.Now()
	c.mu.Unlock()
}

func (c *Client) isIdle(timeout time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastActive) > timeout
}

func (s *Server) broadcaster() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			s.clientsMu.RLock()
			for _, client := range s.clients {
				close(client.outbound)
			}
			s.clientsMu.RUnlock()
			return

		case msg := <-s.messages:
			s.clientsMu.RLock()
			for _, client := range s.clients {
				select {
				case client.outbound <- msg:
				default:
					log.Printf("Client %s is lagging, scheduling removal", client.ID)
					go func(c *Client) {
						s.leaving <- c
					}(client)
				}
			}
			s.clientsMu.RUnlock()

		case client := <-s.entering:
			s.clientsMu.Lock()
			s.clients[client.ID] = client
			log.Printf("Client %s entered. Total clients: %d", client.ID, len(s.clients))
			s.clientsMu.Unlock()

		case client := <-s.leaving:
			s.clientsMu.Lock()
			if _, ok := s.clients[client.ID]; ok {
				delete(s.clients, client.ID)
				close(client.outbound)
				log.Printf("Client %s left. Total clients: %d", client.ID, len(s.clients))
			}
			s.clientsMu.Unlock()
		}
	}
}

func (s *Server) idleChecker() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.clientsMu.RLock()
			for _, client := range s.clients {
				if client.isIdle(s.config.IdleTimeout) {
					log.Printf("Client %s idle, disconnecting", client.ID)
					client.conn.Close()
				}
			}
			s.clientsMu.RUnlock()
		}
	}
}

func generateMessageID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func main() {
	config := DefaultConfig()

	flag.StringVar(&config.ListenAddr, "addr", config.ListenAddr, "Listen address")
	flag.BoolVar(&config.TLSEnabled, "tls", config.TLSEnabled, "Enable TLS")
	flag.StringVar(&config.TLSCertFile, "cert", "server.crt", "TLS certificate file")
	flag.StringVar(&config.TLSKeyFile, "key", "server.key", "TLS key file")
	flag.IntVar(&config.MaxMessageSize, "max-msg", config.MaxMessageSize, "Maximum message size")
	flag.IntVar(&config.MaxClients, "max-clients", config.MaxClients, "Maximum number of clients")
	flag.IntVar(&config.RateLimit, "rate-limit", config.RateLimit, "Rate limit (messages per minute)")
	flag.DurationVar(&config.IdleTimeout, "idle-timeout", config.IdleTimeout, "Idle timeout duration")
	flag.Parse()

	if config.TLSEnabled {
		if _, err := os.Stat(config.TLSCertFile); os.IsNotExist(err) {
			log.Printf("Warning: TLS certificate file not found: %s", config.TLSCertFile)
			log.Println("For testing, generate certificates with:")
			log.Println("  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes")
			log.Fatalln("Exiting due to missing TLS certificates")
		}
		if _, err := os.Stat(config.TLSKeyFile); os.IsNotExist(err) {
			log.Fatalf("TLS key file not found: %s", config.TLSKeyFile)
		}
	}

	log.Println("=== Chat Server Configuration ===")
	log.Printf("Address: %s", config.ListenAddr)
	log.Printf("TLS Enabled: %v", config.TLSEnabled)
	log.Printf("Max Message Size: %d bytes", config.MaxMessageSize)
	log.Printf("Max Clients: %d", config.MaxClients)
	log.Printf("Rate Limit: %d messages per %v", config.RateLimit, config.RateLimitWindow)
	log.Printf("Idle Timeout: %v", config.IdleTimeout)
	log.Println("=================================")

	server := NewServer(config)
	ctx := context.Background()

	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func connectToServer(addr string, useTLS bool) (net.Conn, error) {
	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		return tls.Dial("tcp", addr, tlsConfig)
	}
	return net.Dial("tcp", addr)
}

func ExampleClient() {
	conn, err := connectToServer("127.0.0.1:8000", false)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	go func() {
		decoder := json.NewDecoder(conn)
		for {
			var msg Message
			if err := decoder.Decode(&msg); err != nil {
				log.Printf("Read error: %v", err)
				return
			}
			fmt.Printf("[%s] %s: %s\n", msg.Timestamp.Format("15:04:05"), msg.From, msg.Content)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fmt.Fprintf(conn, "%s\n", scanner.Text())
	}
}
