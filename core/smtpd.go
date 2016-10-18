package core

import (
	"crypto/tls"
	"log"
	"net"
	"path"
	"plugin"

	"github.com/toorop/tmail/core"
)

// Smtpd SMTP Server
type Smtpd struct {
	dsn dsn
}

// NewSmtpd returns a new SmtpServer
func NewSmtpd(d dsn) *Smtpd {
	return &Smtpd{d}
}

// ListenAndServe launch server
func (s *Smtpd) ListenAndServe() {
	var listener net.Listener
	var err error
	var tlsConfig *tls.Config
	var newClientPlugin func(s *core.SMTPServerSession) (bool, error)

	// Plugin
	// load Plugin
	p, err := plugin.Open("newclient.so")
	if err != nil {
		log.Fatalf("ERROR: unable to load plugin - %s", err)
	} else {
		f, err := p.Lookup("Run")
		if err != nil {
			log.Fatalln("unnable to lookup Run symbol on plugin newclient - " + err.Error())
		}
		newClientPlugin = f.(func(s *core.SMTPServerSession) (bool, error))
	}

	// SSL ?
	if s.dsn.ssl {
		cert, err := tls.LoadX509KeyPair(path.Join(GetBasePath(), "ssl/server.crt"), path.Join(GetBasePath(), "ssl/server.key"))
		if err != nil {
			log.Fatalln("unable to load SSL keys for smtpd.", "dsn:", s.dsn.tcpAddr, "ssl", s.dsn.ssl, "err:", err)
		}
		// TODO: http://fastah.blackbuck.mobi/blog/securing-https-in-go/
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}
		listener, err = tls.Listen(s.dsn.tcpAddr.Network(), s.dsn.tcpAddr.String(), tlsConfig)
		if err != nil {
			log.Fatalln("unable to create TLS listener.", err)
		}
	} else {
		listener, err = net.Listen(s.dsn.tcpAddr.Network(), s.dsn.tcpAddr.String())
		if err != nil {
			log.Fatalln("unable to create listener")
		}
	}
	if err != nil {
		log.Fatalln(err)
	} else {
		defer listener.Close()
		for {
			conn, error := listener.Accept()
			if error != nil {
				log.Println("Client error: ", error)
			} else {
				go func(conn net.Conn) {
					ChSmtpSessionsCount <- 1
					defer func() { ChSmtpSessionsCount <- -1 }()
					sss, err := NewSMTPServerSession(conn, s.dsn.ssl, newClientPlugin)
					if err != nil {
						log.Println("unable to get new SmtpServerSession.", err)
					} else {
						sss.handle()
					}
				}(conn)
			}
		}
	}
}
