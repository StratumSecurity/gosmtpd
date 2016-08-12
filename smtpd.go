// Adapted from https://github.com/gleez/smtpd

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type State int

var commands = map[string]bool{
	"HELO":     true,
	"EHLO":     true,
	"MAIL":     true,
	"RCPT":     true,
	"DATA":     true,
	"RSET":     true,
	"SEND":     true,
	"SOML":     true,
	"SAML":     true,
	"VRFY":     true,
	"EXPN":     true,
	"HELP":     true,
	"NOOP":     true,
	"QUIT":     true,
	"TURN":     true,
	"AUTH":     true,
	"STARTTLS": true,
}

// SMTPConfig houses the SMTP server configuration - not using pointers
// so that I can pass around copies of the object safely.
type SMTPConfig struct {
	Ip4address      string
	Ip4port         int
	Domain          string
	AllowedHosts    string
	TrustedHosts    string
	MaxRecipients   int
	MaxIdleSeconds  int
	MaxClients      int
	MaxMessageBytes int
	PubKey          string
	PrvKey          string
	Debug           bool
	DebugPath       string
}

// Real server code starts here
type Server struct {
	outChan         chan<- Message
	listenAddr      string
	listenPort      int
	domain          string
	maxRecips       int
	maxIdleSeconds  int
	maxMessageBytes int
	storeMessages   bool
	listener        net.Listener
	shutdown        bool
	waitgroup       *sync.WaitGroup
	timeout         time.Duration
	allowedHosts    map[string]bool
	trustedHosts    map[string]bool
	maxClients      int
	UseTLS          bool
	TLSConfig       tls.Config
	ForceTLS        bool
	Debug           bool
	DebugPath       string
	sem             chan int // currently active clients
}

type Client struct {
	server     *Server
	state      State
	helo       string
	from       string
	recipients []string
	response   string
	remoteHost string
	sendError  error
	data       string
	subject    string
	hash       string
	time       int64
	tls_on     bool
	conn       net.Conn
	bufin      *bufio.Reader
	bufout     *bufio.Writer
	kill_time  int64
	errors     int
	id         int64
	tlsConn    *tls.Conn
	trusted    bool
}

// Init a new Client object
func NewServer(output chan<- Message, cfg SMTPConfig) *Server {
	var allowedHosts = make(map[string]bool, 15)
	var trustedHosts = make(map[string]bool, 15)

	// map the allow hosts for easy lookup
	if arr := strings.Split(cfg.AllowedHosts, ","); len(arr) > 0 {
		for i := 0; i < len(arr); i++ {
			allowedHosts[strings.Trim(arr[i], " ")] = true
		}
	}
	// map the allow hosts for easy lookup
	if arr := strings.Split(cfg.TrustedHosts, ","); len(arr) > 0 {
		for i := 0; i < len(arr); i++ {
			trustedHosts[net.ParseIP(arr[i]).String()] = true
		}
	}

	// sem is an active clients channel used for counting clients
	maxClients := make(chan int, cfg.MaxClients)

	s := &Server{
		outChan:         output,
		listenAddr:      cfg.Ip4address,
		listenPort:      cfg.Ip4port,
		domain:          cfg.Domain,
		maxRecips:       cfg.MaxRecipients,
		maxIdleSeconds:  cfg.MaxIdleSeconds,
		maxMessageBytes: cfg.MaxMessageBytes,
		waitgroup:       new(sync.WaitGroup),
		allowedHosts:    allowedHosts,
		trustedHosts:    trustedHosts,
		Debug:           cfg.Debug,
		DebugPath:       cfg.DebugPath,
		sem:             maxClients,
	}

	fmt.Printf("Loading the certificate: %s\n", cfg.PubKey)
	cert, err := tls.LoadX509KeyPair(cfg.PubKey, cfg.PrvKey)
	if err != nil {
		fmt.Printf("There was a problem with loading the certificate: %s\n", err)
	} else {
		s.TLSConfig = tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ServerName:   s.domain,
		}
		s.UseTLS = true
		//s.TLSConfig  .Rand = rand.Reader
	}
	return s
}

func (s *Server) WriteMessage(msg Message) {
	s.outChan <- msg
}

// Main listener loop
func (s *Server) Start() {

	defer s.Stop()
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%v:%v", s.listenAddr, s.listenPort))
	if err != nil {
		fmt.Printf("Failed to build tcp4 address: %v\n", err)
		// TODO More graceful early-shutdown procedure
		//panic(err)
		s.Stop()
		return
	}

	// Start listening for SMTP connections
	fmt.Printf("SMTP listening on TCP4 %v\n", addr)
	s.listener, err = net.ListenTCP("tcp4", addr)
	if err != nil {
		fmt.Printf("SMTP failed to start tcp4 listener: %v\n", err)
		// TODO More graceful early-shutdown procedure
		//panic(err)
		s.Stop()
		return
	}

	var tempDelay time.Duration
	var clientId int64

	// Handle incoming connections
	for clientId = 1; ; clientId++ {
		if conn, err := s.listener.Accept(); err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				// Temporary error, sleep for a bit and try again
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				fmt.Printf("SMTP accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			} else {
				if s.shutdown {
					fmt.Printf("SMTP listener shutting down on request\n")
					return
				}
				// TODO Implement a max error counter before shutdown?
				// or maybe attempt to restart smtpd
				panic(err)
			}
		} else {
			tempDelay = 0
			s.waitgroup.Add(1)
			fmt.Printf("There are now %s serving goroutines\n", strconv.Itoa(runtime.NumGoroutine()))
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

			s.sem <- 1 // Wait for active queue to drain.
			go s.handleClient(&Client{
				state:      1,
				server:     s,
				conn:       conn,
				remoteHost: host,
				time:       time.Now().Unix(),
				bufin:      bufio.NewReader(conn),
				bufout:     bufio.NewWriter(conn),
				id:         clientId,
			})
		}
	}
}

// Stop requests the SMTP server closes it's listener
func (s *Server) Stop() {
	fmt.Printf("SMTP shutdown requested, connections will be drained\n")
	s.shutdown = true
	s.listener.Close()
}

// Drain causes the caller to block until all active SMTP sessions have finished
func (s *Server) Drain() {
	s.waitgroup.Wait()
	fmt.Printf("SMTP connections drained\n")
}

func (s *Server) closeClient(c *Client) {
	c.bufout.Flush()
	time.Sleep(200 * time.Millisecond)
	c.conn.Close()
	<-s.sem // Done; enable next client to run.
}

func (s *Server) killClient(c *Client) {
	c.kill_time = time.Now().Unix()
}

func (s *Server) handleClient(c *Client) {
	fmt.Printf("SMTP Connection from %v, starting session <%v>\n", c.conn.RemoteAddr(), c.id)

	defer func() {
		s.closeClient(c)
		s.waitgroup.Done()
	}()

	c.greet()

	// check if client on trusted hosts
	if s.trustedHosts[net.ParseIP(c.remoteHost).String()] {
		c.logInfo("Remote Client is Trusted: <%s>", c.remoteHost)
		c.trusted = true
	}

	// This is our command reading loop
	for i := 0; i < 100; i++ {
		if c.state == 2 {
			// Special case, does not use SMTP command format
			c.processData()
			continue
		}

		line, err := c.readLine()
		if err == nil {
			if cmd, arg, ok := c.parseCmd(line); ok {
				c.handle(cmd, arg, line)
			}
		} else {
			// readLine() returned an error
			if err == io.EOF {
				c.logWarn("Got EOF while in state %v", c.state)
				break
			}
			// not an EOF
			c.logWarn("Connection error: %v", err)
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.Write("221", "Idle timeout, bye bye")
				break
			}

			c.Write("221", "Connection error, sorry")
			break
		}

		if c.kill_time > 1 || c.errors > 3 {
			return
		}
	}

	c.logInfo("Closing connection")
}

// TODO support nested MIME content
func (c *Client) ParseMessage(mimeParser bool) Message {
	arr := make([]*Path, 0)
	for _, path := range c.recipients {
		arr = append(arr, PathFromString(path))
	}

	msg := Message{
		From:    PathFromString(c.from),
		To:      arr,
		Created: time.Now(),
		Ip:      c.remoteHost,
		Unread:  true,
		Starred: false,
	}

	if mimeParser {
		msg.Content = &Content{Size: len(c.data), Headers: make(map[string][]string, 0), Body: c.data}
		// Read mail using standard mail package
		if rm, err := mail.ReadMessage(bytes.NewBufferString(c.data)); err == nil {
			fmt.Printf("Reading Mail Message\n")
			msg.Content.Size = len(c.data)
			msg.Content.Headers = rm.Header
			msg.Subject = MimeHeaderDecode(rm.Header.Get("Subject"))

			if mt, p, err := mime.ParseMediaType(rm.Header.Get("Content-Type")); err == nil {
				if strings.HasPrefix(mt, "multipart/") {
					fmt.Printf("Parsing MIME Message\n")
					MIMEBody := &MIMEBody{Parts: make([]*MIMEPart, 0)}
					if err := ParseMIME(MIMEBody, rm.Body, p["boundary"], &msg); err == nil {
						fmt.Printf("Got multiparts %d\n", len(MIMEBody.Parts))
						msg.MIME = MIMEBody
					}
				} else {
					setMailBody(rm, &msg)
				}
			} else {
				setMailBody(rm, &msg)
			}
		} else {
			msg.Content.TextBody = c.data
		}
	} else {
		msg.Content = ContentFromString(c.data)
	}

	randomID := make([]byte, 16)
	rand.Read(randomID)
	hexStr := hex.EncodeToString(randomID)
	recd := fmt.Sprintf(
		"from %s ([%s]) by %s (Smtpd)\r\n  for <%s>; %s\r\n",
		c.helo, c.remoteHost, c.server.domain, hexStr+"@"+c.server.domain, time.Now().Format(time.RFC1123Z))
	//msg.Content.Headers["Delivered-To"]  = []string{msg.To}
	msg.Content.Headers["Message-ID"] = []string{hexStr + "@" + c.server.domain}
	msg.Content.Headers["Received"] = []string{recd}
	msg.Content.Headers["Return-Path"] = []string{"<" + c.from + ">"}
	return msg
}

// Commands are dispatched to the appropriate handler functions.
func (c *Client) handle(cmd string, arg string, line string) {
	c.logTrace("In state %d, got command '%s', args '%s'", c.state, cmd, arg)

	// Check against valid SMTP commands
	if cmd == "" {
		c.Write("500", "Speak up")
		//return
	}

	if cmd != "" && !commands[cmd] {
		c.Write("500", fmt.Sprintf("Syntax error, %v command unrecognized", cmd))
		c.logWarn("Unrecognized command: %v", cmd)
	}

	switch cmd {
	case "SEND", "SOML", "SAML", "EXPN", "HELP", "TURN":
		// These commands are not implemented in any state
		c.Write("502", fmt.Sprintf("%v command not implemented", cmd))
		c.logWarn("Command %v not implemented by Gsmtpd", cmd)
		//return
	case "HELO":
		c.greetHandler(cmd, arg)
		//return
	case "EHLO":
		c.greetHandler(cmd, arg)
		//return
	case "MAIL":
		c.mailHandler(cmd, arg)
		//return
	case "RCPT":
		c.rcptHandler(cmd, arg)
		//return
	case "VRFY":
		c.Write("252", "Cannot VRFY user, but will accept message")
		//return
	case "NOOP":
		c.Write("250", "I have sucessfully done nothing")
		//return
	case "RSET":
		// Reset session
		c.logTrace("Resetting session state on RSET request")
		c.reset()
		c.Write("250", "Session reset")
		//return
	case "DATA":
		c.dataHandler(cmd, arg)
		//return
	case "QUIT":
		c.Write("221", "Goodnight and good luck")
		c.server.killClient(c)
		//return
	case "AUTH":
		c.authHandler(cmd, arg)
		//c.logInfo("Got LOGIN authentication response: '%s', switching to AUTH state", arg)
		//c.Write("334", "UGFzc3dvcmQ6")
	case "STARTTLS":
		c.tlsHandler()
		//return
	default:
		c.errors++
		if c.errors > 3 {
			c.Write("500", "Too many unrecognized commands")
			c.server.killClient(c)
		}
	}
}

// GREET state -> waiting for HELO
func (c *Client) greetHandler(cmd string, arg string) {
	switch cmd {
	case "HELO":
		domain, err := parseHelloArgument(arg)
		if err != nil {
			c.Write("501", "Domain/address argument required for HELO")
			return
		}
		c.helo = domain
		c.Write("250", fmt.Sprintf("Hello %s", domain))
		c.state = 1
	case "EHLO":
		domain, err := parseHelloArgument(arg)
		if err != nil {
			c.Write("501", "Domain/address argument required for EHLO")
			return
		}

		if c.server.UseTLS && !c.tls_on {
			c.Write("250", "Hello "+domain+"["+c.remoteHost+"]", "PIPELINING", "8BITMIME", "STARTTLS", "AUTH EXTERNAL CRAM-MD5 LOGIN PLAIN", fmt.Sprintf("SIZE %v", c.server.maxMessageBytes))
			//c.Write("250", "Hello "+domain+"["+c.remoteHost+"]", "8BITMIME", fmt.Sprintf("SIZE %v", c.server.maxMessageBytes), "HELP")
		} else {
			c.Write("250", "Hello "+domain+"["+c.remoteHost+"]", "PIPELINING", "8BITMIME", "AUTH EXTERNAL CRAM-MD5 LOGIN PLAIN", fmt.Sprintf("SIZE %v", c.server.maxMessageBytes))
		}
		c.helo = domain
		c.state = 1
	default:
		c.ooSeq(cmd)
	}
}

// READY state -> waiting for MAIL
func (c *Client) mailHandler(cmd string, arg string) {
	if cmd == "MAIL" {
		if c.helo == "" {
			c.Write("502", "Please introduce yourself first.")
			return
		}

		// Match FROM, while accepting '>' as quoted pair and in double quoted strings
		// (?i) makes the regex case insensitive, (?:) is non-grouping sub-match
		re := regexp.MustCompile("(?i)^FROM:\\s*<((?:\\\\>|[^>])+|\"[^\"]+\"@[^>]+)>( [\\w= ]+)?$")
		m := re.FindStringSubmatch(arg)
		if m == nil {
			c.Write("501", "Was expecting MAIL arg syntax of FROM:<address>")
			c.logWarn("Bad MAIL argument: %q", arg)
			return
		}

		from := m[1]
		_, _, err := ParseEmailAddress(from)
		if err != nil {
			c.Write("501", "Bad sender address syntax")
			c.logWarn("Bad address as MAIL arg: %q, %s", from, err)
			return
		}

		// This is where the client may put BODY=8BITMIME, but we already
		// read the DATA as bytes, so it does not effect our processing.
		if m[2] != "" {
			args, ok := c.parseArgs(m[2])
			if !ok {
				c.Write("501", "Unable to parse MAIL ESMTP parameters")
				c.logWarn("Bad MAIL argument: %q", arg)
				return
			}
			if args["SIZE"] != "" {
				size, err := strconv.ParseInt(args["SIZE"], 10, 32)
				if err != nil {
					c.Write("501", "Unable to parse SIZE as an integer")
					c.logWarn("Unable to parse SIZE %q as an integer", args["SIZE"])
					return
				}
				if int(size) > c.server.maxMessageBytes {
					c.Write("552", "Max message size exceeded")
					c.logWarn("Client wanted to send oversized message: %v", args["SIZE"])
					return
				}
			}
		}
		c.from = from
		c.logInfo("Mail from: %v", from)
		c.Write("250", fmt.Sprintf("Roger, accepting mail from <%v>", from))
		c.state = 1
	} else {
		c.ooSeq(cmd)
	}
}

// MAIL state -> waiting for RCPTs followed by DATA
func (c *Client) rcptHandler(cmd string, arg string) {
	if cmd == "RCPT" {
		if c.from == "" {
			c.Write("502", "Missing MAIL FROM command.")
			return
		}

		if (len(arg) < 4) || (strings.ToUpper(arg[0:3]) != "TO:") {
			c.Write("501", "Was expecting RCPT arg syntax of TO:<address>")
			c.logWarn("Bad RCPT argument: %q", arg)
			return
		}

		// This trim is probably too forgiving
		recip := strings.Trim(arg[3:], "<> ")
		_, host, err := ParseEmailAddress(recip)
		if err != nil {
			c.Write("501", "Bad recipient address syntax")
			c.logWarn("Bad address as RCPT arg: %q, %s", recip, err)
			return
		}

		// check if on allowed hosts if client ip not trusted
		if !c.server.allowedHosts[host] && !c.trusted {
			c.logWarn("Domain not allowed: <%s>", host)
			c.Write("510", "Recipient address not allowed")
			return
		}

		if len(c.recipients) >= c.server.maxRecips {
			c.logWarn("Maximum limit of %v recipients reached", c.server.maxRecips)
			c.Write("552", fmt.Sprintf("Maximum limit of %v recipients reached", c.server.maxRecips))
			return
		}

		c.recipients = append(c.recipients, recip)
		c.logInfo("Recipient: %v", recip)
		c.Write("250", fmt.Sprintf("I'll make sure <%v> gets this", recip))
		return
	} else {
		c.ooSeq(cmd)
	}
}

func (c *Client) authHandler(cmd string, arg string) {
	if cmd == "AUTH" {
		if c.helo == "" {
			c.Write("502", "Please introduce yourself first.")
			return
		}

		if arg == "" {
			c.Write("502", "Missing parameter")
			return
		}

		c.logTrace("Got AUTH command, staying in MAIL state %s", arg)
		parts := strings.Fields(arg)
		mechanism := strings.ToUpper(parts[0])

		/*	scanner := bufio.NewScanner(c.bufin)
			line := scanner.Text()
			c.logTrace("Read Line %s", line)
			if !scanner.Scan() {
				return
			}
		*/
		switch mechanism {
		case "LOGIN":
			c.Write("334", "VXNlcm5hbWU6")
		case "PLAIN":
			c.logInfo("Got PLAIN authentication: %s", mechanism)
			c.Write("235", "Authentication successful")
		case "CRAM-MD5":
			c.logInfo("Got CRAM-MD5 authentication, switching to AUTH state")
			c.Write("334", "PDQxOTI5NDIzNDEuMTI4Mjg0NzJAc291cmNlZm91ci5hbmRyZXcuY211LmVkdT4=")
		case "EXTERNAL":
			c.logInfo("Got EXTERNAL authentication: %s", strings.TrimPrefix(arg, "EXTERNAL "))
			c.Write("235", "Authentication successful")
		default:
			c.logTrace("Unsupported authentication mechanism %v", arg)
			c.Write("504", "Unsupported authentication mechanism")
		}
	} else {
		c.ooSeq(cmd)
	}
}

func (c *Client) tlsHandler() {
	if c.tls_on {
		c.Write("502", "Already running in TLS")
		return
	}

	if !c.server.UseTLS {
		c.Write("502", "TLS not supported")
		return
	}

	fmt.Printf("Ready to start TLS\n")
	c.Write("220", "Ready to start TLS")

	// upgrade to TLS
	var tlsConn *tls.Conn
	tlsConn = tls.Server(c.conn, &c.server.TLSConfig)
	err := tlsConn.Handshake() // not necessary to call here, but might as well

	if err == nil {
		//c.conn   = net.Conn(tlsConn)
		c.conn = tlsConn
		c.bufin = bufio.NewReader(c.conn)
		c.bufout = bufio.NewWriter(c.conn)
		c.tls_on = true

		// Reset envelope as a new EHLO/HELO is required after STARTTLS
		c.reset()

		// Reset deadlines on the underlying connection before I replace it
		// with a TLS connection
		c.conn.SetDeadline(time.Time{})
		c.flush()
	} else {
		c.logWarn("Could not TLS handshake:%v", err)
		c.Write("550", "Handshake error")
	}

	c.state = 1
}

// DATA
func (c *Client) dataHandler(cmd string, arg string) {
	c.logTrace("Enter dataHandler %d", c.state)

	if arg != "" {
		c.Write("501", "DATA command should not have any arguments")
		c.logWarn("Got unexpected args on DATA: %q", arg)
		return
	}

	if len(c.recipients) > 0 {
		// We have recipients, go to accept data
		c.logTrace("Go ahead we have recipients %d", len(c.recipients))
		c.Write("354", "Go ahead. End your data with <CR><LF>.<CR><LF>")
		c.state = 2
		return
	} else {
		c.Write("502", "Missing RCPT TO command.")
		return
	}

	return
}

func (c *Client) processData() {
	var msg string

	for {
		buf := make([]byte, 1024)
		n, err := c.conn.Read(buf)

		if n == 0 {
			c.logInfo("Connection closed by remote host\n")
			c.server.killClient(c)
			break
		}

		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.Write("221", "Idle timeout, bye bye")
			}
			c.logInfo("Error reading from socket: %s\n", err)
			break
		}

		text := string(buf[0:n])
		msg += text

		// If we have debug true, save the mail to file for review
		if c.server.Debug {
			c.saveMailDatatoFile(msg)
		}

		if len(msg) > c.server.maxMessageBytes {
			c.logWarn("Maximum DATA size exceeded (%s)", strconv.Itoa(c.server.maxMessageBytes))
			c.Write("552", "Maximum message size exceeded")
			c.reset()
			return
		}

		//Postfix bug ugly hack (\r\n.\r\nQUIT\r\n)
		if strings.HasSuffix(msg, "\r\n.\r\n") || strings.LastIndex(msg, "\r\n.\r\n") != -1 {
			break
		}
	}

	if len(msg) > 0 {
		c.logTrace("Got EOF, storing message and switching to MAIL state")
		msg = strings.TrimSuffix(msg, "\r\n.\r\n")
		c.data = msg

		// TODO - Figure out a way to make this mimeparser=true parameter configurable
		c.server.WriteMessage(c.ParseMessage(true))
		c.Write("250", "Mail accepted for delivery")
		c.logInfo("Message size %v bytes", len(msg))
	}

	c.reset()
}

func (c *Client) reject() {
	c.Write("421", "Too busy. Try again later.")
	c.server.closeClient(c)
}

func (c *Client) enterState(state State) {
	c.state = state
	c.logTrace("Entering state %v", state)
}

func (c *Client) greet() {
	c.Write("220", fmt.Sprintf("%v Gleez SMTP # %s (%s) %s", c.server.domain, strconv.FormatInt(c.id, 10), strconv.Itoa(len(c.server.sem)), time.Now().Format(time.RFC1123Z)))
	c.state = 1
}

func (c *Client) flush() {
	c.conn.SetWriteDeadline(c.nextDeadline())
	c.bufout.Flush()
	c.conn.SetReadDeadline(c.nextDeadline())
}

// Calculate the next read or write deadline based on maxIdleSeconds
func (c *Client) nextDeadline() time.Time {
	return time.Now().Add(time.Duration(c.server.maxIdleSeconds) * time.Second)
}

func (c *Client) Write(code string, text ...string) {
	c.conn.SetDeadline(c.nextDeadline())
	if len(text) == 1 {
		c.logTrace(">> Sent %d bytes: %s >>", len(text[0]), text[0])
		c.conn.Write([]byte(code + " " + text[0] + "\r\n"))
		c.bufout.Flush()
		return
	}
	for i := 0; i < len(text)-1; i++ {
		c.logTrace(">> Sent %d bytes: %s >>", len(text[i]), text[i])
		c.conn.Write([]byte(code + "-" + text[i] + "\r\n"))
	}
	c.logTrace(">> Sent %d bytes: %s >>", len(text[len(text)-1]), text[len(text)-1])
	c.conn.Write([]byte(code + " " + text[len(text)-1] + "\r\n"))

	c.bufout.Flush()
}

// readByteLine reads a line of input into the provided buffer. Does
// not reset the Buffer - please do so prior to calling.
func (c *Client) readByteLine(buf *bytes.Buffer) error {
	if err := c.conn.SetReadDeadline(c.nextDeadline()); err != nil {
		return err
	}
	for {
		line, err := c.bufin.ReadBytes('\r')
		if err != nil {
			return err
		}
		buf.Write(line)
		// Read the next byte looking for '\n'
		c, err := c.bufin.ReadByte()
		if err != nil {
			return err
		}
		buf.WriteByte(c)
		if c == '\n' {
			// We've reached the end of the line, return
			return nil
		}
		// Else, keep looking
	}
	// Should be unreachable
}

// Reads a line of input
func (c *Client) readLine() (line string, err error) {
	if err = c.conn.SetReadDeadline(c.nextDeadline()); err != nil {
		return "", err
	}

	line, err = c.bufin.ReadString('\n')
	if err != nil {
		return "", err
	}
	c.logTrace("<< %v <<", strings.TrimRight(line, "\r\n"))
	return line, nil
}

func (c *Client) parseCmd(line string) (cmd string, arg string, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	l := len(line)
	switch {
	case strings.Index(line, "STARTTLS") == 0:
		return "STARTTLS", "", true
	case l == 0:
		return "", "", true
	case l < 4:
		c.logWarn("Command too short: %q", line)
		return "", "", false
	case l == 4:
		return strings.ToUpper(line), "", true
	case l == 5:
		// Too long to be only command, too short to have args
		c.logWarn("Mangled command: %q", line)
		return "", "", false
	}
	// If we made it here, command is long enough to have args
	if line[4] != ' ' {
		// There wasn't a space after the command?
		c.logWarn("Mangled command: %q", line)
		return "", "", false
	}
	// I'm not sure if we should trim the args or not, but we will for now
	//return strings.ToUpper(line[0:4]), strings.Trim(line[5:], " "), true
	return strings.ToUpper(line[0:4]), strings.Trim(line[5:], " \n\r"), true
}

// parseArgs takes the arguments proceeding a command and files them
// into a map[string]string after uppercasing each key.  Sample arg
// string:
//		" BODY=8BITMIME SIZE=1024"
// The leading space is mandatory.
func (c *Client) parseArgs(arg string) (args map[string]string, ok bool) {
	args = make(map[string]string)
	re := regexp.MustCompile(" (\\w+)=(\\w+)")
	pm := re.FindAllStringSubmatch(arg, -1)
	if pm == nil {
		c.logWarn("Failed to parse arg string: %q")
		return nil, false
	}
	for _, m := range pm {
		args[strings.ToUpper(m[1])] = m[2]
	}
	c.logTrace("ESMTP params: %v", args)
	return args, true
}

func (c *Client) reset() {
	c.state = 1
	c.from = ""
	c.helo = ""
	c.recipients = nil
}

func (c *Client) ooSeq(cmd string) {
	c.Write("503", fmt.Sprintf("Command %v is out of sequence", cmd))
	c.logWarn("Wasn't expecting %v here", cmd)
}

// Session specific logging methods
func (c *Client) logTrace(msg string, args ...interface{}) {
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *Client) logInfo(msg string, args ...interface{}) {
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *Client) logWarn(msg string, args ...interface{}) {
	// Update metrics
	//expWarnsTotal.Add(1)
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *Client) logError(msg string, args ...interface{}) {
	// Update metrics
	//expErrorsTotal.Add(1)
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func parseHelloArgument(arg string) (string, error) {
	domain := arg
	if idx := strings.IndexRune(arg, ' '); idx >= 0 {
		domain = arg[:idx]
	}
	if domain == "" {
		return "", fmt.Errorf("Invalid domain")
	}
	return domain, nil
}

// Debug mail data to file
func (c *Client) saveMailDatatoFile(msg string) {
	filename := fmt.Sprintf("%s/%s-%s-%s.raw", c.server.DebugPath, c.remoteHost, c.from, time.Now().Format("Jan-2-2006-3:04:00pm"))
	f, err := os.Create(filename)

	if err != nil {
		fmt.Printf("Error saving file %v\n", err)
	}

	defer f.Close()
	n, err := io.WriteString(f, msg)

	if err != nil {
		fmt.Printf("Error saving file %v: %v\n", n, err)
	}
}
