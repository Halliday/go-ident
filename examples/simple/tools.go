package main

import (
	"bytes"
	"html"
	"io"
	"log"
	"mime/quotedprintable"
	"net/smtp"
	"regexp"
	"strings"
)

func PrintEmailToLog(addr string, a smtp.Auth, from string, to []string, msg []byte) error {

	log.Println("> You've got mail!")
	log.Printf("> FROM: %s", from)
	log.Printf("> TO: %s", to)
	log.Println("> BODY:")

	i := bytes.Index(msg, emailHeadBodySplit)
	if i == -1 {
		log.Println("> (invalid email message)")
	}
	quotedBody := msg[i+4:]
	body, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewBuffer(quotedBody)))

	for _, line := range strings.Split(string(body), "\n") {
		log.Println(">   " + line)
	}

	matches := hrefRegexp.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		log.Print(string(body))
		log.Print("> The email contained no links.")
	}
	for _, m := range matches {
		log.Printf("> Link: %s", html.UnescapeString(m[1]))
	}

	return nil
}

var emailHeadBodySplit = []byte{'\r', '\n', '\r', '\n'}

var hrefRegexp = regexp.MustCompile(`href="(.+)"`)
