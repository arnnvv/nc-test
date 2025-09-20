package main

import (
	"log"
	"net"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]uint8, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHi\r\n"))
}

func main() {
	listner, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	defer listner.Close()
	for {
		conn, err := listner.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn)
	}
}
