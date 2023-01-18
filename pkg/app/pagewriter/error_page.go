package pagewriter

import (
	"fmt"
	"html/template"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// errorMessages are default error messages for each of the different
// http status codes expected to be rendered in the error page.
var errorMessages = map[int]string{
	http.StatusInternalServerError: "Oops! Something went wrong. For more information contact your server administrator.",
	http.StatusNotFound:            "We could not find the resource you were looking for.",
	http.StatusForbidden:           "You do not have permission to access this resource.",
	http.StatusUnauthorized:        "You need to be logged in to access this resource.",
}

// errorPageWriter is used to render error pages.
type errorPageWriter struct {
	// template is the error page HTML template.
	template *template.Template

	// proxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	proxyPrefix string

	// footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	footer string

	// version is the OAuth2 Proxy version to be used in the default footer.
	version string

	// debug determines whether errors pages should be rendered with detailed
	// errors.
	debug bool
}

// ErrorPageOpts bundles up all the content needed to write the Error Page
type ErrorPageOpts struct {
	// HTTP status code
	Status int
	// Redirect URL for "Go back" and "Sign in" buttons
	RedirectURL string
	// The UUID of the request
	RequestID string
	// App Error shown in debug mode
	AppError string
	// Generic error messages shown in non-debug mode
	Messages []interface{}
}

// WriteErrorPage writes an error page to the given response writer.
// It uses the passed redirectURL to give users the option to go back to where
// they originally came from or try signing in again.
func (e *errorPageWriter) WriteErrorPage(rw http.ResponseWriter, opts ErrorPageOpts) {
	rw.WriteHeader(opts.Status)

	// We allow unescaped template.HTML since it is user configured options
	/* #nosec G203 */
	data := struct {
		Title       string
		Message     string
		ProxyPrefix string
		StatusCode  int
		Redirect    string
		RequestID   string
		Footer      template.HTML
		Version     string
	}{
		// http.StatusText 변경이 필요 (ims 294994)
		//Title:       http.StatusText(opts.Status),
		Title:       customStatusText(opts.Status),
		Message:     e.getMessage(opts.Status, opts.AppError, opts.Messages...),
		ProxyPrefix: e.proxyPrefix,
		StatusCode:  opts.Status,
		Redirect:    opts.RedirectURL,
		RequestID:   opts.RequestID,
		Footer:      template.HTML(e.footer),
		Version:     e.version,
	}

	if err := e.template.Execute(rw, data); err != nil {
		logger.Printf("Error rendering error template: %v", err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
func customStatusText(code int) string {
	switch code {
	case http.StatusContinue:
		return "Continue"
	case http.StatusSwitchingProtocols:
		return "Switching Protocols"
	case http.StatusProcessing:
		return "Processing"
	case http.StatusEarlyHints:
		return "Early Hints"
	case http.StatusOK:
		return "OK"
	case http.StatusCreated:
		return "Created"
	case http.StatusAccepted:
		return "Accepted"
	case http.StatusNonAuthoritativeInfo:
		return "Non-Authoritative Information"
	case http.StatusNoContent:
		return "No Content"
	case http.StatusResetContent:
		return "Reset Content"
	case http.StatusPartialContent:
		return "Partial Content"
	case http.StatusMultiStatus:
		return "Multi-Status"
	case http.StatusAlreadyReported:
		return "Already Reported"
	case http.StatusIMUsed:
		return "IM Used"
	case http.StatusMultipleChoices:
		return "Multiple Choices"
	case http.StatusMovedPermanently:
		return "Moved Permanently"
	case http.StatusFound:
		return "Found"
	case http.StatusSeeOther:
		return "See Other"
	case http.StatusNotModified:
		return "Not Modified"
	case http.StatusUseProxy:
		return "Use Proxy"
	case http.StatusTemporaryRedirect:
		return "Temporary Redirect"
	case http.StatusPermanentRedirect:
		return "Permanent Redirect"
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusPaymentRequired:
		return "Payment Required"
	case http.StatusForbidden:
		return "잘못된 접근입니다."
	case http.StatusNotFound:
		return "Not Found"
	case http.StatusMethodNotAllowed:
		return "Method Not Allowed"
	case http.StatusNotAcceptable:
		return "Not Acceptable"
	case http.StatusProxyAuthRequired:
		return "Proxy Authentication Required"
	case http.StatusRequestTimeout:
		return "Request Timeout"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusGone:
		return "Gone"
	case http.StatusLengthRequired:
		return "Length Required"
	case http.StatusPreconditionFailed:
		return "Precondition Failed"
	case http.StatusRequestEntityTooLarge:
		return "Request Entity Too Large"
	case http.StatusRequestURITooLong:
		return "Request URI Too Long"
	case http.StatusUnsupportedMediaType:
		return "Unsupported Media Type"
	case http.StatusRequestedRangeNotSatisfiable:
		return "Requested Range Not Satisfiable"
	case http.StatusExpectationFailed:
		return "Expectation Failed"
	case http.StatusTeapot:
		return "I'm a teapot"
	case http.StatusMisdirectedRequest:
		return "Misdirected Request"
	case http.StatusUnprocessableEntity:
		return "Unprocessable Entity"
	case http.StatusLocked:
		return "Locked"
	case http.StatusFailedDependency:
		return "Failed Dependency"
	case http.StatusTooEarly:
		return "Too Early"
	case http.StatusUpgradeRequired:
		return "Upgrade Required"
	case http.StatusPreconditionRequired:
		return "Precondition Required"
	case http.StatusTooManyRequests:
		return "Too Many Requests"
	case http.StatusRequestHeaderFieldsTooLarge:
		return "Request Header Fields Too Large"
	case http.StatusUnavailableForLegalReasons:
		return "Unavailable For Legal Reasons"
	case http.StatusInternalServerError:
		return "Internal Server Error"
	case http.StatusNotImplemented:
		return "Not Implemented"
	case http.StatusBadGateway:
		return "Bad Gateway"
	case http.StatusServiceUnavailable:
		return "Service Unavailable"
	case http.StatusGatewayTimeout:
		return "Gateway Timeout"
	case http.StatusHTTPVersionNotSupported:
		return "HTTP Version Not Supported"
	case http.StatusVariantAlsoNegotiates:
		return "Variant Also Negotiates"
	case http.StatusInsufficientStorage:
		return "Insufficient Storage"
	case http.StatusLoopDetected:
		return "Loop Detected"
	case http.StatusNotExtended:
		return "Not Extended"
	case http.StatusNetworkAuthenticationRequired:
		return "Network Authentication Required"
	default:
		return ""
	}
}

// ProxyErrorHandler is used by the upstream ReverseProxy to render error pages
// when there are issues with upstream servers.
// It is expected to always render a bad gateway error.
func (e *errorPageWriter) ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error) {
	logger.Errorf("Error proxying to upstream server: %v", proxyErr)
	scope := middlewareapi.GetRequestScope(req)
	e.WriteErrorPage(rw, ErrorPageOpts{
		Status:      http.StatusBadGateway,
		RedirectURL: "", // The user is already logged in and has hit an upstream error. Makes no sense to redirect in this case.
		RequestID:   scope.RequestID,
		AppError:    proxyErr.Error(),
		Messages:    []interface{}{"There was a problem connecting to the upstream server."},
	})
}

// getMessage creates the message for the template parameters.
// If the errorPagewriter.Debug is enabled, the application error takes precedence.
// Otherwise, any messages will be used.
// The first message is expected to be a format string.
// If no messages are supplied, a default error message will be used.
func (e *errorPageWriter) getMessage(status int, appError string, messages ...interface{}) string {
	if e.debug {
		return appError
	}
	if len(messages) > 0 {
		format := fmt.Sprintf("%v", messages[0])
		return fmt.Sprintf(format, messages[1:]...)
	}
	if msg, ok := errorMessages[status]; ok {
		return msg
	}
	return "Unknown error"
}
