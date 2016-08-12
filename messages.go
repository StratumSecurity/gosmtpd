package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/alexcesaro/mail/quotedprintable"
	"github.com/sloonz/go-iconv"
)

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
		convstr, err := iconv.Conv(str, "UTF-8", charset)
		if err == nil {
			return convstr
		}
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
		if convstr, err := iconv.Conv(str, "UTF-8", charset); err == nil {
			return convstr
		}
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
