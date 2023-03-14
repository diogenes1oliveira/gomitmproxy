package gomitmproxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/AdguardTeam/golibs/log"
	"github.com/diogenes1oliveira/gomitmproxy/proxyutil"
)

// ExtractBasicAuth parses a Basic authentication header value
func ExtractBasicAuth(headerValue string) (username string, password string, err error) {
	if headerValue == "" {
		return "", "", fmt.Errorf("no authorization")

	}

	if !strings.HasPrefix(headerValue, "Basic ") {
		return "", "", fmt.Errorf("unrecognized authorization type")
	}

	credentialsBase64 := headerValue[len("Basic "):]
	credentialsBytes, err := base64.StdEncoding.DecodeString(credentialsBase64)
	if err != nil {
		return "", "", fmt.Errorf("malformed authorization credentials")
	}
	credentials := string(credentialsBytes)
	username, password, _ = strings.Cut(credentials, ":")

	if username == "" {
		return "", "", fmt.Errorf("no authorization username")
	}

	return username, password, nil
}

// BasicPasswordAuthorizer returns an HTTP authorization header value according to RFC2617.
// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt:
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64 encoded string
// in the credentials."
// It is not meant to be urlencoded.
func BasicPasswordAuthorizer(username, password string) AuthorizationFunc {
	return func(proxyAuth string) (username string, err error) {
		authUsername, authPassword, err := ExtractBasicAuth(proxyAuth)
		if err != nil {
			return "", err
		}
		if username != authUsername || (password != "" && password != authPassword) {
			return "", fmt.Errorf("wrong username or password")
		}

		return username, nil
	}
}

// newNotAuthorizedResponse creates a new "407 (Proxy Authentication Required)"
// response.
func newNotAuthorizedResponse(session *Session, message string) *http.Response {

	body := strings.NewReader(message)
	res := proxyutil.NewResponse(http.StatusProxyAuthRequired, body, session.req)

	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate.
	res.Header.Set("Proxy-Authenticate", "Basic")
	return res
}

// authorize checks the "Proxy-Authorization" header and returns true if the
// request is authorized. If it returns false, it also returns the response that
// should be written to the client.
func (p *Proxy) authorize(session *Session) (bool, *http.Response) {
	if session.ctx.parent != nil {
		// If we're here, it means the connection is authorized already.
		return true, nil
	}

	if p.Authorize == nil {
		return true, nil
	}

	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization.
	proxyAuth := session.req.Header.Get("Proxy-Authorization")
	username, err := p.Authorize(proxyAuth)

	if err != nil {
		response := newNotAuthorizedResponse(session, err.Error())
		return false, response
	}

	session.Ctx().SetProp("username", username)
	session.SetProp("username", username)
	log.Debug("set username to %s", username)
	return true, nil
}
