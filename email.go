package ident

import (
	"bytes"
	"html/template"
	"mime/quotedprintable"
	"net/smtp"
	"strconv"

	"github.com/halliday/go-openid"
)

var defaultSmtPort = 25

func (s *Server) prepareMail(subject string, to string, template *template.Template, data interface{}) (addr string, auth smtp.Auth, msg []byte, err error) {
	addr = s.EmailHost + ":"
	if s.EmailHostPort == 0 {
		addr += strconv.Itoa(defaultSmtPort)
	} else {
		addr += strconv.Itoa(s.EmailHostPort)
	}
	if s.EmailEnableAuthentication {
		auth = smtp.PlainAuth("", s.EmailUsername, s.EmailPassword, s.EmailHost)
	}
	var b bytes.Buffer
	b.WriteString("From: ")
	b.WriteString(s.EmailFromDisplayName)
	b.WriteString(" <")
	b.WriteString(s.EmailFrom)
	b.WriteString(">\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(subject)
	b.WriteString("\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"\r\n",
	)

	if err = template.Execute(quotedprintable.NewWriter(&b), data); err != nil {
		return addr, auth, nil, err
	}

	return addr, auth, b.Bytes(), err
}

type Email struct {
	*openid.Userinfo
	RedirectUri string
}

//
