// Adapted from https://github.com/gleez/smtpd

package smtpd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexcesaro/mail/quotedprintable"
	"gopkg.in/iconv.v1"
)

// Defaults for server configuration options
const (
	DefaultDomain         = "local"
	DefaultMaxRecipients  = 100
	DefaultMaxIdleSeconds = 300
	DefaultMaxClients     = 500
	DefaultMaxMsgBytes    = 20480000
)

type state int

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

// PermissionManager is an interface that should be implemented by users of this library
// to provide customized functionality for determining whether a client is trusted to
// send emails to the server and if the specified recipient is allowed.
type PermissionManager interface {
	// Determine, given a client's connecting IP, whether that client is trusted to send emails.
	IsTrusted(string) bool
	// Determine, given a recipient email domain, whether clients are allowed
	// to send emails to addresses at that domain.
	IsAllowed(string) bool
}

// ServerConfig contains information used to configure a Server.  Most of the fields
// have reasonable defaults for usage on localhost.
type ServerConfig struct {
	BindAddress     string
	BindPort        int
	Domain          string
	MaxRecipients   int
	MaxIdleSeconds  int
	MaxClients      int
	MaxMessageBytes int
	PublicKeyFile   string
	PrivateKeyFile  string
}

// Message represents a received email with all of its processed contents.
type Message struct {
	Subject     string
	From        *Path
	To          []*Path
	Created     time.Time
	Attachments []*Attachment
	IP          string
	Content     *Content
	MIME        *MIMEBody
	Starred     bool
	Unread      bool
}

// Path describes the path an email took to be received by a Server.
type Path struct {
	Relays  []string
	Mailbox string
	Domain  string
	Params  string
}

// Content holds the meaningful body and headers of a Message.
type Content struct {
	Headers  map[string][]string
	TextBody string
	HTMLBody string
	Size     int
	Body     string
}

// MIMEBody contains the parts of a Message's MIME contents.
type MIMEBody struct {
	Parts []*MIMEPart
}

// MIMEPart contains all of the descriptive information and content of a
// MIME part of an email.
type MIMEPart struct {
	Headers          map[string][]string
	Body             string
	FileName         string
	ContentType      string
	Charset          string
	MIMEVersion      string
	TransferEncoding string
	Disposition      string
	Size             int
}

// Attachment contains the contents of an attachment included in an email.
type Attachment struct {
	Body             string
	FileName         string
	ContentType      string
	Charset          string
	MIMEVersion      string
	TransferEncoding string
	Size             int
}

// Server holds state about an SMTP server including everything needed to process
// messages and use TLS.  It also includes a channel through which messages, i.e.
// emails, will be written upon receipt for processing by a user of the library.
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
	maxClients      int
	useTLS          bool
	tlsConfig       tls.Config
	sem             chan int // currently active clients
}

// Client contains information about a client sending an email to a Server.
type client struct {
	server     *Server
	state      state
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
	tlsOn      bool
	conn       net.Conn
	bufin      *bufio.Reader
	bufout     *bufio.Writer
	killTime   int64
	errors     int
	id         int64
	tlsConn    *tls.Conn
	trusted    bool
}

// The default PermissionManager used by a Server that has not been told to do
// and of the client filtering a production system would want to do.
type allowOnlyLocalhost struct{}

// Trust only clients connecting via localhost to send emails.
func (a allowOnlyLocalhost) IsTrusted(clientIP string) bool {
	return clientIP == "localhost" || clientIP == "127.0.0.1"
}

// Allow clients only to send emails to localhost.
func (a allowOnlyLocalhost) IsAllowed(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}

// NewServer is the constructor for a new Server that will write emails through
// the provided channel, and process incoming emails according to the provided
// configuration.  The only ServerConfig fields that are required are BindAddress
// and BindPort.
func NewServer(output chan<- Message, cfg ServerConfig) *Server {
	// Apply defaults to any fields that were left out of the config
	if cfg.Domain == "" {
		cfg.Domain = DefaultDomain
	}
	if cfg.MaxRecipients == 0 {
		cfg.MaxRecipients = DefaultMaxRecipients
	}
	if cfg.MaxIdleSeconds == 0 {
		cfg.MaxIdleSeconds = DefaultMaxIdleSeconds
	}
	if cfg.MaxClients == 0 {
		cfg.MaxClients = DefaultMaxClients
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = DefaultMaxMsgBytes
	}

	// sem is an active clients channel used for counting clients
	maxClients := make(chan int, cfg.MaxClients)

	s := &Server{
		outChan:         output,
		listenAddr:      cfg.BindAddress,
		listenPort:      cfg.BindPort,
		domain:          cfg.Domain,
		maxRecips:       cfg.MaxRecipients,
		maxIdleSeconds:  cfg.MaxIdleSeconds,
		maxMessageBytes: cfg.MaxMessageBytes,
		waitgroup:       new(sync.WaitGroup),
		sem:             maxClients,
	}

	fmt.Printf("Loading the certificate: %s\n", cfg.PublicKeyFile)
	cert, err := tls.LoadX509KeyPair(cfg.PublicKeyFile, cfg.PrivateKeyFile)
	if err != nil {
		fmt.Printf("There was a problem with loading the certificate: %s\n", err)
	} else {
		s.tlsConfig = tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ServerName:   s.domain,
		}
		s.useTLS = true
		//s.tlsConfig  .Rand = rand.Reader
	}
	return s
}

func (s *Server) writeMessage(msg Message) {
	s.outChan <- msg
}

// Start begins the server's main listener loop, preparing it to accept incoming emails.
// It accepts a single argument, which must be an instance of a type that implements PermissionManager.
// If nil is provided, it will default to an implementing type that only allows emails from
// localhost.
func (s *Server) Start(permissionChecker PermissionManager) {
	defer s.Stop()
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%v:%v", s.listenAddr, s.listenPort))
	if err != nil {
		fmt.Printf("Failed to build tcp4 address: %v\n", err)
		s.Stop()
		return
	}

	if permissionChecker == nil {
		permissionChecker = allowOnlyLocalhost{}
	}

	// Start listening for SMTP connections
	fmt.Printf("SMTP listening on TCP4 %v\n", addr)
	s.listener, err = net.ListenTCP("tcp4", addr)
	if err != nil {
		fmt.Printf("SMTP failed to start tcp4 listener: %v\n", err)
		s.Stop()
		return
	}

	var tempDelay time.Duration
	var clientID int64

	// Handle incoming connections
	for clientID = 1; ; clientID++ {
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
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

			s.sem <- 1 // Wait for active queue to drain.
			go s.handleClient(permissionChecker, &client{
				state:      1,
				server:     s,
				conn:       conn,
				remoteHost: host,
				time:       time.Now().Unix(),
				bufin:      bufio.NewReader(conn),
				bufout:     bufio.NewWriter(conn),
				id:         clientID,
			})
		}
	}
}

// Stop requests the SMTP server closes it's listener.
func (s *Server) Stop() {
	fmt.Printf("SMTP shutdown requested, connections will be drained\n")
	s.shutdown = true
	s.listener.Close()
}

// Drain causes the caller to block until all active SMTP sessions have finished.
func (s *Server) Drain() {
	s.waitgroup.Wait()
	fmt.Printf("SMTP connections drained\n")
}

func (s *Server) closeClient(c *client) {
	c.bufout.Flush()
	time.Sleep(200 * time.Millisecond)
	c.conn.Close()
	<-s.sem // Done; enable next client to run.
}

func (s *Server) killClient(c *client) {
	c.killTime = time.Now().Unix()
}

func (s *Server) handleClient(permissionChecker PermissionManager, c *client) {
	fmt.Printf("SMTP Connection from %v, starting session <%v>\n", c.conn.RemoteAddr(), c.id)

	defer func() {
		s.closeClient(c)
		s.waitgroup.Done()
	}()

	c.greet()

	// check if client on trusted hosts
	if permissionChecker.IsTrusted(net.ParseIP(c.remoteHost).String()) {
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
				c.handle(cmd, arg, line, permissionChecker)
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

		if c.killTime > 1 || c.errors > 3 {
			return
		}
	}

	c.logInfo("Closing connection")
}

// TODO support nested MIME content
func (c *client) parseMessage(mimeParser bool) Message {
	var arr []*Path
	for _, path := range c.recipients {
		arr = append(arr, pathFromString(path))
	}

	msg := Message{
		From:    pathFromString(c.from),
		To:      arr,
		Created: time.Now(),
		IP:      c.remoteHost,
		Unread:  true,
		Starred: false,
	}

	(func() {
		if !mimeParser {
			msg.Content = contentFromString(c.data)
			return
		}
		msg.Content = &Content{Size: len(c.data), Headers: make(map[string][]string, 0), Body: c.data}
		readMsg, err := mail.ReadMessage(bytes.NewBufferString(c.data))
		if err != nil {
			msg.Content.TextBody = c.data
			return
		}
		mimetype, parsed, err := mime.ParseMediaType(readMsg.Header.Get("Content-Type"))
		if err == nil && strings.HasPrefix(mimetype, "multipart/") {
			mimeBody := &MIMEBody{Parts: make([]*MIMEPart, 0)}
			err = parseMIME(mimeBody, readMsg.Body, parsed["boundary"], &msg)
			if err == nil {
				fmt.Println("Got", len(mimeBody.Parts), "multiparts")
				msg.MIME = mimeBody
			}
			return
		}
		setMailBody(readMsg, &msg)
	})()

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
func (c *client) handle(cmd string, arg string, line string, permissionChecker PermissionManager) {
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
		c.rcptHandler(cmd, arg, permissionChecker)
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
func (c *client) greetHandler(cmd string, arg string) {
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

		if c.server.useTLS && !c.tlsOn {
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
func (c *client) mailHandler(cmd string, arg string) {
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
		_, err := mail.ParseAddress(from)
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
func (c *client) rcptHandler(cmd string, arg string, permissionChecker PermissionManager) {
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
		addr, err := mail.ParseAddress(recip)
		if err != nil {
			c.Write("501", "Bad recipient address syntax")
			c.logWarn("Bad address as RCPT arg: %q, %s", recip, err)
			return
		}
		host := strings.Split(addr.Address, "@")[1]

		// check if on allowed hosts if client ip not trusted
		if !permissionChecker.IsAllowed(host) && !c.trusted {
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
	}
	c.ooSeq(cmd)
}

func (c *client) authHandler(cmd string, arg string) {
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

func (c *client) tlsHandler() {
	if c.tlsOn {
		c.Write("502", "Already running in TLS")
		return
	}

	if !c.server.useTLS {
		c.Write("502", "TLS not supported")
		return
	}

	fmt.Printf("Ready to start TLS\n")
	c.Write("220", "Ready to start TLS")

	// upgrade to TLS
	var tlsConn *tls.Conn
	tlsConn = tls.Server(c.conn, &c.server.tlsConfig)
	err := tlsConn.Handshake() // not necessary to call here, but might as well

	if err == nil {
		//c.conn   = net.Conn(tlsConn)
		c.conn = tlsConn
		c.bufin = bufio.NewReader(c.conn)
		c.bufout = bufio.NewWriter(c.conn)
		c.tlsOn = true

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
func (c *client) dataHandler(cmd string, arg string) {
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
	} else {
		c.Write("502", "Missing RCPT TO command.")
	}
}

func (c *client) processData() {
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
		c.server.writeMessage(c.parseMessage(true))
		c.Write("250", "Mail accepted for delivery")
		c.logInfo("Message size %v bytes", len(msg))
	}

	c.reset()
}

func (c *client) reject() {
	c.Write("421", "Too busy. Try again later.")
	c.server.closeClient(c)
}

func (c *client) enterState(state state) {
	c.state = state
	c.logTrace("Entering state %v", state)
}

func (c *client) greet() {
	c.Write("220", fmt.Sprintf("%v Gleez SMTP # %s (%s) %s", c.server.domain, strconv.FormatInt(c.id, 10), strconv.Itoa(len(c.server.sem)), time.Now().Format(time.RFC1123Z)))
	c.state = 1
}

func (c *client) flush() {
	c.conn.SetWriteDeadline(c.nextDeadline())
	c.bufout.Flush()
	c.conn.SetReadDeadline(c.nextDeadline())
}

// Calculate the next read or write deadline based on maxIdleSeconds
func (c *client) nextDeadline() time.Time {
	return time.Now().Add(time.Duration(c.server.maxIdleSeconds) * time.Second)
}

func (c *client) Write(code string, text ...string) {
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
func (c *client) readByteLine(buf *bytes.Buffer) error {
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
func (c *client) readLine() (line string, err error) {
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

func (c *client) parseCmd(line string) (cmd string, arg string, ok bool) {
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
func (c *client) parseArgs(arg string) (args map[string]string, ok bool) {
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

func (c *client) reset() {
	c.state = 1
	c.from = ""
	c.helo = ""
	c.recipients = nil
}

func (c *client) ooSeq(cmd string) {
	c.Write("503", fmt.Sprintf("Command %v is out of sequence", cmd))
	c.logWarn("Wasn't expecting %v here", cmd)
}

// Session specific logging methods
func (c *client) logTrace(msg string, args ...interface{}) {
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *client) logInfo(msg string, args ...interface{}) {
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *client) logWarn(msg string, args ...interface{}) {
	// Update metrics
	//expWarnsTotal.Add(1)
	fmt.Printf("SMTP[%v]<%v> %v\n", c.remoteHost, c.id, fmt.Sprintf(msg, args...))
}

func (c *client) logError(msg string, args ...interface{}) {
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

func pathFromString(path string) *Path {
	var relays []string
	email := path
	if strings.Contains(path, ":") {
		x := strings.SplitN(path, ":", 2)
		r, e := x[0], x[1]
		email = e
		relays = strings.Split(r, ",")
	}
	mailbox, domain := "", ""
	if strings.Contains(email, "@") {
		x := strings.SplitN(email, "@", 2)
		mailbox, domain = x[0], x[1]
	} else {
		mailbox = email
	}

	return &Path{
		Relays:  relays,
		Mailbox: mailbox,
		Domain:  domain,
		Params:  "", // FIXME?
	}
}

func parseMIME(MIMEBody *MIMEBody, reader io.Reader, boundary string, message *Message) error {
	mr := multipart.NewReader(reader, boundary)

	for {
		mrp, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				// This is a clean end-of-message signal
				break
				//log.Fatal("Error eof %s", err)
			}
			return err
		}

		if len(mrp.Header) == 0 {
			// Empty header probably means the part didn't using the correct trailing "--"
			// syntax to close its boundary.  We will let this slide if this this the
			// last MIME part.
			if _, err := mr.NextPart(); err != nil {
				if err == io.EOF || strings.HasSuffix(err.Error(), "EOF") {
					// This is what we were hoping for
					break
				} else {
					return fmt.Errorf("Error at boundary %v: %v", boundary, err)
				}
			}

			return fmt.Errorf("Empty header at boundary %v", boundary)
		}

		ctype := mrp.Header.Get("Content-Type")
		if ctype == "" {
			fmt.Errorf("Missing Content-Type at boundary %v", boundary)
		}

		mediatype, mparams, err := mime.ParseMediaType(ctype)
		if err != nil {
			return err
		}

		encoding := mrp.Header.Get("Content-Transfer-Encoding")
		// Figure out our disposition, filename
		disposition, dparams, err := mime.ParseMediaType(mrp.Header.Get("Content-Disposition"))

		if strings.HasPrefix(mediatype, "multipart/") && mparams["boundary"] != "" {
			// Content is another multipart
			parseMIME(MIMEBody, mrp, mparams["boundary"], message)
		} else {
			if n, body, err := partbuf(mrp); err == nil {
				part := &MIMEPart{Size: int(n), Headers: mrp.Header, Body: string(body), FileName: ""}
				// Disposition is optional
				part.Disposition = disposition
				part.ContentType = mediatype
				part.TransferEncoding = encoding

				if mparams["charset"] != "" {
					part.Charset = mparams["charset"]
				}

				if disposition == "attachment" || disposition == "inline" {
					//log.LogTrace("Found attachment: '%s'", disposition)
					part.FileName = mimeHeaderDecode(dparams["filename"])

					if part.FileName == "" && mparams["name"] != "" {
						part.FileName = mimeHeaderDecode(mparams["name"])
					}
				}

				// Save attachments
				if disposition == "attachment" && len(part.FileName) > 0 {
					fmt.Printf("Found attachment: '%s'", disposition)
					//db.messages.find({ 'attachments.id': "54200a938b1864264c000005" }, {"attachments.$" : 1})
					attachment := &Attachment{
						Body:             string(body),
						FileName:         part.FileName,
						Charset:          part.Charset,
						ContentType:      mediatype,
						TransferEncoding: encoding,
						Size:             int(n),
					}
					message.Attachments = append(message.Attachments, attachment)
				} else {
					MIMEBody.Parts = append(MIMEBody.Parts, part)
				}

				//use mediatype; ctype will have 'text/plain; charset=UTF-8'
				// attachments might be plain text content, so make sure of it
				if mediatype == "text/plain" && disposition != "attachment" {
					message.Content.TextBody = mimeBodyDecode(string(body), part.Charset, part.TransferEncoding)
				}

				if mediatype == "text/html" && disposition != "attachment" {
					message.Content.HTMLBody = mimeBodyDecode(string(body), part.Charset, part.TransferEncoding)
				}
			} else {
				fmt.Printf("Error Processing MIME message: <%s>", err)
			}
		}
	}

	return nil
}

func contentFromString(data string) *Content {
	fmt.Printf("Parsing Content from string: <%d>", len(data))
	x := strings.SplitN(data, "\r\n\r\n", 2)
	h := make(map[string][]string, 0)

	if len(x) == 2 {
		headers, body := x[0], x[1]
		hdrs := strings.Split(headers, "\r\n")
		var lastHdr = ""
		for _, hdr := range hdrs {
			if lastHdr != "" && strings.HasPrefix(hdr, " ") {
				h[lastHdr][len(h[lastHdr])-1] = h[lastHdr][len(h[lastHdr])-1] + hdr
			} else if strings.Contains(hdr, ": ") {
				y := strings.SplitN(hdr, ": ", 2)
				key, value := y[0], y[1]
				// TODO multiple header fields
				h[key] = []string{value}
				lastHdr = key
			} else {
				fmt.Printf("Found invalid header: '%s'", hdr)
			}
		}
		//log.LogTrace("Found body: '%s'", body)
		return &Content{
			Size:    len(data),
			Headers: h,
			Body:    body,
			//Body:   "",
		}
	}
	return &Content{
		Size:     len(data),
		Headers:  h,
		Body:     x[0],
		TextBody: x[0],
	}
}

func partbuf(reader io.Reader) (int64, []byte, error) {
	// Read bytes into buffer
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(reader)
	if err != nil {
		return 0, nil, err
	}

	return n, buf.Bytes(), nil
}

// Decode strings in Mime header format
// eg. =?ISO-2022-JP?B?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=
func mimeHeaderDecode(str string) string {
	//str, err := mail.DecodeRFC2047Word(str)
	str, charset, err := quotedprintable.DecodeHeader(str)
	charset = strings.ToUpper(charset)

	if err == nil && charset != "UTF-8" {
		charset = fixCharset(charset)
		// eg. charset can be "ISO-2022-JP"
		converter, err := iconv.Open("UTF-8", charset)
		if err != nil {
			return str
		}
		return converter.ConvString(str)
	}
	return str
}

func mimeBodyDecode(str string, charset string, encoding string) string {
	if encoding == "" {
		return str
	}

	encoding = strings.ToLower(encoding)
	if encoding == "base64" {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return str
		}
		str = string(dec)
	}

	if charset == "" {
		return str
	}

	charset = strings.ToUpper(charset)
	if charset != "UTF-8" {
		charset = fixCharset(charset)
		// eg. charset can be "ISO-2022-JP"
		converter, err := iconv.Open("UTF-8", charset)
		if err != nil {
			return str
		}
		return converter.ConvString(str)
	}
	return str
}

func fixCharset(charset string) string {
	reg, _ := regexp.Compile(`[_:.\/\\]`)
	fixedCharset := reg.ReplaceAllString(charset, "-")
	// Fix charset
	// borrowed from http://squirrelmail.svn.sourceforge.net/viewvc/squirrelmail/trunk/squirrelmail/include/languages.php?revision=13765&view=markup
	// OE ks_c_5601_1987 > cp949
	fixedCharset = strings.Replace(fixedCharset, "ks-c-5601-1987", "cp949", -1)
	// Moz x-euc-tw > euc-tw
	fixedCharset = strings.Replace(fixedCharset, "x-euc", "euc", -1)
	// Moz x-windows-949 > cp949
	fixedCharset = strings.Replace(fixedCharset, "x-windows_", "cp", -1)
	// windows-125x and cp125x charsets
	fixedCharset = strings.Replace(fixedCharset, "windows-", "cp", -1)
	// ibm > cp
	fixedCharset = strings.Replace(fixedCharset, "ibm", "cp", -1)
	// iso-8859-8-i -> iso-8859-8
	fixedCharset = strings.Replace(fixedCharset, "iso-8859-8-i", "iso-8859-8", -1)
	if charset != fixedCharset {
		return fixedCharset
	}
	return charset
}

func setMailBody(rm *mail.Message, msg *Message) {
	if _, body, err := partbuf(rm.Body); err == nil {
		if bodyIsHTML(rm) {
			msg.Content.HTMLBody = string(body)
		} else {
			msg.Content.TextBody = string(body)
		}
	}
}

func bodyIsHTML(mr *mail.Message) bool {
	ctype := mr.Header.Get("Content-Type")
	if ctype == "" {
		return false
	}

	mediatype, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		return false
	}

	// Figure out our disposition, filename
	disposition, _, err := mime.ParseMediaType(mr.Header.Get("Content-Disposition"))

	if mediatype == "text/html" && disposition != "attachment" && err == nil {
		return true
	}

	return false
}
