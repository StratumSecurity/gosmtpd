# gosmtpd

This library is a refactored fork of [gleez/smtpd](https://github.com/gleez/smtpd), itself a fork of
[flashmob/go-guerrilla](https://github.com/flashmob/go-guerrilla).  It provides an incredibly simple
interface to an SMTP server that pushes processed emails to a user-supplied channel, allowing you
to make use of those emails in whatever way suits your use case.

## Example

The following example illustrates how simple it can be to setup and run an SMTP server that will
allow any connecting client to send an email to any domain.

```go
package main

import (
  "fmt"
  "github.com/StratumSecurity/gosmtpd"
)

// allowAll satisfies the smtpd.PermissionManager interface
type allowAll struct{}

func (a allowAll) IsTrusted(s string) bool {
  return true
}

func (a allowAll) IsAllowed(s string) bool {
  return true
}

func handleMessages(in <-chan smtpd.Message) {
  for {
    msg := <-in
    fmt.Println("Got message\n", msg, "\n")
  }
}

func main() {
  messages := make(chan smtpd.Message)
  server := smtpd.NewServer(messages, smtpd.ServerConfig{
    BindAddress: "127.0.0.1",
    BindPort:    25,
  })
  go handleMessages(messages)
  server.Start(allowAll{})
  server.Drain()
}
```

You could then write an email to this running server by doing the following, using Telnet.

```
$ telnet 127.0.0.1 25

helo 127.0.0.1
mail from:<testing@site.com>
rcpt to:<someone@else.com>
data
Subject: Hello world

This is the body of an email!

.

```

After pressing enter/return following the single period (.), you'll see the server output the
received message struct.

## Motivation and Features

The motivation for creating this library, by refactoring [gleez/smtpd](https://github.com/gleez/smtpd)
was to provide an incredibly simple interface for running a reasonably featureful SMTP server without
any of the use case-specific functionality that existing codebases include, like the web interface, Nginx
XClient support, or database persistence.  The library still provides:

1. TLS Support (STARTTLS)
2. Support for SMTP Auth and PIPELINING
3. Multipart MIME
4. Attachments
5. UTF8 in subjects and bodies

This is all on top of providing an excellent and simple interface.

## API Index

1. [Constants](https://github.com/StratumSecurity/gosmtpd#constants)
2. [Functions](https://github.com/StratumSecurity/gosmtpd#functions)
  * [NewServer](https://github.com/StratumSecurity/gosmtpd#newserver)
3. [Types](https://github.com/StratumSecurity/gosmtpd#types<Paste>)
  * [PermissionManager](https://github.com/StratumSecurity/gosmtpd#permissionmanager)
    * [IsTrusted](https://github.com/StratumSecurity/gosmtpd#permissionmanageristrusted)
    * [IsAllowed](https://github.com/StratumSecurity/gosmtpd#permissionmanagerisallowed)
  * [Server](https://github.com/StratumSecurity/gosmtpd#server)
    * [Start](https://github.com/StratumSecurity/gosmtpd#serverstart)
    * [Stop](https://github.com/StratumSecurity/gosmtpd#serverstop)
    * [Drain](https://github.com/StratumSecurity/gosmtpd#serverdrain)
  * [ServerConfig](https://github.com/StratumSecurity/gosmtpd#serverconfig)
  * [Message](https://github.com/StratumSecurity/gosmtpd#message)
  * [Path](https://github.com/StratumSecurity/gosmtpd#path)
  * [Content](https://github.com/StratumSecurity/gosmtpd#content)
  * [MIMEBody](https://github.com/StratumSecurity/gosmtpd#mimebody)
  * [MIMEPart](https://github.com/StratumSecurity/gosmtpd#mimepart)
  * [Attachment](https://github.com/StratumSecurity/gosmtpd#attachment)

### Constants

```go
const (
	DefaultDomain         = "local"
	DefaultMaxRecipients  = 100
	DefaultMaxIdleSeconds = 300
	DefaultMaxClients     = 500
	DefaultMaxMsgBytes    = 20480000
)
```

### Functions

#### NewServer

```go
func NewServer(output chan<- Message, cfg ServerConfig) *Server
```

Creates a new SMTP that will send emails to the provided channel.

### Types

#### PermissionManager

```go
type PermissionManager interface {
	IsTrusted(string) bool
	IsAllowed(string) bool
}
```

Instead of accepting comma-separated lists of hosts to trust to send email or allow to be sent
emails, implementations of PermissionManager have a lot more flexibility.

##### PermissionManager.IsTrusted

```go
IsTrusted(string) bool
```

Called by the SMTP server with a client's IP address (and port number) as a string formatted
like

    <IP address>:<port>

that should return true if the client should be allowed to send emails using the server, or
else false to deny access.

##### PermissionManager.IsAllowed

```go
IsAllowed(string) bool
```

Called by the SMTP server with the domain, such as `site.com`, of the email address that a client
wants to send an email to.  It should return true if clients are allowed to send to that domain,
or else false to deny access.

#### Server

```go
type Server struct {
  // Private fields omitted
}
```

##### Server.Start

```go
func (s *Server) Start(permissionChecker PermissionManager)
```

Starts the SMTP server with a `PermissionManager` that will determine who can send emails and to
whom.  If `permissionChecker` is `nil`, it will default to a localhost-only `PermissionManager`
that will only allow local clients to send to 127.0.0.1, useful for testing purposes.

##### Server.Stop

```go
func (s *Server) Stop()
```

Signals to the SMTP server to stop running and accepting client connections.

##### Server.Drain

```go
func (s *Server) Drain()
```

Causes the caller to block until all active SMTP sessions have finished.

#### ServerConfig

```go
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
```

#### Message

```go
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
```

#### Path

```go
type Path struct {
	Relays  []string
	Mailbox string
	Domain  string
	Params  string
}
```

#### Content

```go
type Content struct {
	Headers  map[string][]string
	TextBody string
	HTMLBody string
	Size     int
	Body     string
}
```

#### MIMEBody

```go
type MIMEBody struct {
	Parts []*MIMEPart
}
```

#### MIMEPart

```go
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
```

#### Attachment

```go
type Attachment struct {
	Body             string
	FileName         string
	ContentType      string
	Charset          string
	MIMEVersion      string
	TransferEncoding string
	Size             int
```
