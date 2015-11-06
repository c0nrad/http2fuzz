// Copyright 2015 Yahoo Inc.
// Licensed under the BSD license, see LICENSE file for terms.
// Written by Stuart Larsen
// http2fuzz - HTTP/2 Fuzzer
package util

import "math/rand"
import "time"

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func PickRandomString(arr []string) string {
	index := rand.Intn(len(arr))
	return arr[index]
}

var HTTPMethods = []string{"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "FOOBAR"}

func RandomMethod() string {
	return PickRandomString(HTTPMethods)
}

var HTTPHeaders = []string{"Accept-Ranges", "Cache-Control", "Connection",
	"Content-Disposition", "Content-Encoding", "Content-Length", "Content-Type",
	"Date", "ETag", "Expires", "Keep-Alive", "Last-Modified", "Location", "Refresh",
	"Server", "Status", "Transfer-Encoding", "", "WWW-Authenticate",
	"Accept", "Accept-Encoding", "Set-Cookie", "Cookie", "ETag", "Cache-Control",
	"Accept-Language", "Authorization", "Cookie", "Depth", "Destination", "Expect", "Host", "If-Match",
	"If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Overwrite", "Range", "Referer",
	"Upgrade", "User-Agent", "Via", "Accept-Charset", "Accept-Datetime",
	"Avoiding", "Connection", "Content-MD5", "Expect", "From", "Host", "Permanent", "Max-Forwards", "Origin",
	"Pragma", "TE", "User-Agent", "Upgrade", "Via", "Warning"}

func RandomHeader() string {
	index := rand.Intn(len(HTTPHeaders))
	return HTTPHeaders[index]
}

var HTTPHeaderValues = []string{
	"gzip", "keep-alive", "en-US", "utf-8", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
	"100-continue", "user@user", "bytes=500-999", "https", "1.1", "http://localhost",
	"https://localhost", "XMLHttpRequest"}

func RandomHeaderValue() string {
	index := rand.Intn(len(HTTPHeaderValues))
	return HTTPHeaderValues[index]
}

var HTTPSchemes = []string{
	"http://", "https://", "ftp://", "mailto://", "aim://", "file://", "dns://",
	"fax://", "imap://", "ldap://", "ldaps://", "smb://", "pop://", "rtsp://", "snmp://",
	"telnet://", "xmpp://", "chrome://", "feed://", "irc://", "mms://", "ssh://",
	"sftp://", "sms://", "url://", "about://", "sip://", "h323://", "tel://",
}

var HTTPFileExtensions = []string{
	".htm", ".html", ".jpg", ".png", ".bmp", ".svg", ".xls", ".doc",
	".ppt", ".swf", ".exe", ".dll", ".so", ".wml", ".mov", ".wmv",
	".avi", ".mp3", ".wav", ".xml", ".php", ".esi",
}

var HTTPOpenTags = []string{
	"<xml>", "<html>", "<script>", "<style>", "<svg>",
}

var HTTPCloseTags = []string{
	"</xml>", "</html>", "</script>", "</style>", "<svg>",
}

var HTTPImageTypes = []string{
	"image/bmp", "image/cmu-raster", "image/fif", "image/florian", "image/g3fax",
	"image/gif", "image/ief", "image/jpeg", "image/jutvision", "image/naplps", "image/pict", "image/pjpeg", "image/png",
	"image/tiff", "image/vasa", "image/vnd.dwg", "image/vnd.fpx", "image/vnd.net-fpx", "image/vnd.rn-realflash",
	"image/vnd.rn-realpix", "image/vnd.wap.wbmp", "image/vnd.xiff", "image/xbm", "image/xpm", "message/rfc822", "model/iges",
	"model/vnd.dwf", "model/vrml", "music/crescendo", "text/asp", "text/css", "text/html", "text/mcf", "text/pascal",
	"text/plain", "text/richtext", "text/scriplet", "text/sgml", "text/tab-separated-values", "text/uri-list", "text/vnd.abc",
	"text/vnd.fmi.flexstor", "text/vnd.rn-realtext", "text/vnd.wap.wml", "text/vnd.wap.wmlscript", "text/webviewhtml",
	"text/xml", "windows/metafile", "www/mime", "xgl/drawing", "xgl/movie",
}

var HTTPResponseHeaders = []string{
	"Accept-Ranges", "Age", "Allow", "Avoiding", "Connection", "Content-Encoding", "Content-Language", "Content-Length",
	"Content-Location", "Content-MD5", "Content-Disposition", "Content-Range", "Content-Type", "Date", "Expires", "Cache-Control",
	"Last-Modified", "Link", "P3P", "Pragma", "Proxy-Authenticate", "Retry-After", "Server", "Status", "Trailer", "Transfer-Encoding",
	"Upgrade", "Vary", "Via", "Warning", "WWW-Authenticate", "Public-Key-Pins", "Set-Cookie", "Cookie", "ETag",
}

var HTTPStatusCodes = []string{
	"100", "101", "200", "201", "202", "203", "204", "205", "206", "300", "301", "302", "303", "304", "305", "307", "400", "401", "402", "403",
	"404", "405", "406", "407", "408", "409", "410", "414", "412", "413", "414", "415", "416", "417", "500", "501", "502", "503", "504", "505",
}
