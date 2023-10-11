package ncCTF

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

func ReadUntil(r *bufio.Reader, ch byte, printLog ...bool) (string, error) {
	// Receive the text message
	line, err := r.ReadString(ch)
	if len(printLog) != 0 && printLog[0] {
		if err != nil {
			log.Fatal(err)
		}
	}
	line = strings.Trim(strings.Trim(line, " "), "\n")
	return line, nil
}

func ReadLines(r *bufio.Reader, lines int, printLog ...bool) error {
	// Receive the text message
	for i := 0; i < lines; i++ {
		line, err := r.ReadString('\n')
		if len(printLog) != 0 && printLog[0] {
			log.Print(line)
			if err != nil {
				log.Fatal(err)
				return err
			}
		}
	}
	return nil
}

func SendLineAfter(conn net.Conn, r *bufio.Reader, ch byte, line string, printLog ...bool) {
	ReadUntil(r, ch, printLog...)
	fmt.Fprintln(conn, line)
}
