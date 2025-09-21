package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const messageBuffer = 10

type client chan<- string

type message struct {
	senderAddr string
	content    string
}

type Server struct {
	listenAddr string
	listener   net.Listener
	wg         sync.WaitGroup

	clients  map[client]bool
	entering chan client
	leaving  chan client
	messages chan message
}

func NewServer(addr string) *Server {
	return &Server{
		listenAddr: addr,
		clients:    make(map[client]bool),
		entering:   make(chan client),
		leaving:    make(chan client),
		messages:   make(chan message, messageBuffer),
	}
}

func (s *Server) Start(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("Starting chat server on %s", s.listenAddr)
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("could not start listener: %w", err)
	}
	s.listener = ln
	log.Printf("Listening on %s", s.listener.Addr())

	s.wg.Add(1)
	go s.runBroadcaster()

	s.wg.Add(1)
	go s.acceptConnections()

	<-ctx.Done()
	log.Println("Shutdown signal received. Closing listener...")

	s.listener.Close()

	s.wg.Wait()
	log.Println("Server shut down gracefully.")
	return nil
}

func (s *Server) runBroadcaster() {
	defer s.wg.Done()
	log.Println("Broadcaster started.")
	for {
		select {
		case msg := <-s.messages:
			log.Printf("Broadcasting message from %s", msg.senderAddr)
			for cli := range s.clients {
				select {
				case cli <- msg.content:
				default:
					log.Printf("Client %p is lagging. Scheduling for removal.", cli)
					go func(c client) { s.leaving <- c }(cli)
				}
			}

		case cli := <-s.entering:
			s.clients[cli] = true
			log.Printf("Client connected. %d clients total.", len(s.clients))

		case cli := <-s.leaving:
			if _, ok := s.clients[cli]; ok {
				delete(s.clients, cli)
				close(cli)
				log.Printf("Client disconnected. %d clients remaining.", len(s.clients))
			}
		}
	}
}

func (s *Server) acceptConnections() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Listener stopped accepting connections: %v", err)
			return
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	ch := make(chan string, messageBuffer)
	s.wg.Add(1)
	go s.clientWriter(conn, ch)

	who := conn.RemoteAddr().String()
	ch <- "Welcome to the chat! Your address is: " + who

	s.messages <- message{who, who + " has arrived"}
	s.entering <- ch

	input := bufio.NewScanner(conn)
	for input.Scan() {
		s.messages <- message{who, who + ": " + input.Text()}
	}

	s.leaving <- ch
	s.messages <- message{who, who + " has left"}

	if err := input.Err(); err != nil {
		log.Printf("Error reading from client %s: %v", who, err)
	}
}

func (s *Server) clientWriter(conn net.Conn, ch <-chan string) {
	defer s.wg.Done()
	for msg := range ch {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintln(conn, msg); err != nil {
			log.Printf("Error writing to client %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

func main() {
	ctx := context.Background()
	server := NewServer("localhost:8000")

	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
