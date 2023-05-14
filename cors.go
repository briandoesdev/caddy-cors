package caddy_cors

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Define the Cors middleware config
type Cors struct {
	// Directive Options
	AllowedOrigins       []string `json:"allowed_origins,omitempty"`
	OverrideExistingCors bool     `json:"override_existing_cors,omitempty"`
	AllowedMethods       []string `json:"allowed_methods,omitempty"`
	AllowCredentials     bool     `json:"allow_credentials,omitempty"`
	MaxAge               int      `json:"max_age,omitempty"`
	AllowedHeaders       []string `json:"allowed_headers,omitempty"`
	ExposedHeaders       []string `json:"exposed_headers,omitempty"`

	// Logger
	logger *zap.Logger
}

// Setup the Cors middleware
func (c *Cors) Provision(ctx caddy.Context) error {
	// Setup the logger
	c.logger = ctx.Logger(c)

	// TODO: Make this configurable?
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{"*"}
		c.logger.Debug("Cors: No allowed origins specified, defaulting to * (all origins)")
	}

	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
		c.logger.Debug("Cors: No allowed methods specified, defaulting to GET, POST, PUT, DELETE, PATCH, OPTIONS")
	}

	// Setting default to 5 seconds as per spec
	// https://fetch.spec.whatwg.org/#http-access-control-max-age
	if c.MaxAge == 0 {
		c.MaxAge = 5
		c.logger.Debug("Cors: No max age specified, defaulting to 5 seconds (as per spec)", zap.Int("max_age", c.MaxAge))
	}

	c.logger.Info("Cors: Configured",
		zap.Strings("allowed_origins", c.AllowedOrigins),
		zap.Bool("override_existing_cors", c.OverrideExistingCors),
		zap.Strings("allowed_methods", c.AllowedMethods),
		zap.Bool("allow_credentials", c.AllowCredentials),
		zap.Int("max_age", c.MaxAge),
		zap.Strings("allowed_headers", c.AllowedHeaders),
		zap.Strings("exposed_headers", c.ExposedHeaders),
	)

	return nil
}

// Validate the Cors middleware config
func (c *Cors) Validate() error {
	// Cap the max age to 24 hours
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
	if c.MaxAge > 86400 {
		c.MaxAge = 86400
		c.logger.Warn("Cors: Max age capped to 24 hours")
	}

	// Check that the HTTP methods are being used correctly
	// The methods need to be a comma separated list of methods
	// Correct: "Get" "Post" "Put" "Delete" "Patch" "Options"
	// Incorrect: "GET, POST, PUT, DELETE, PATCH, OPTIONS"
	for _, method := range c.AllowedMethods {
		if strings.Contains(method, ",") {
			// TODO: Fix this for the user by splitting the string
			return fmt.Errorf("Cors: Allowed methods formatted incorrectly, should be a comma separated list of methods")
		}
	}

	return nil
}

// Process the HTTP request adding our CORS headers
func (c Cors) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	origin := r.Header.Get("Origin")
	c.logger.Debug("Cors: Origin", zap.String("origin", origin))

	// If no Origin header is present, it is not a cross-origin request from a browser
	if origin == "" {
		c.logger.Debug("Cors: No origin header, skipping")
		return next.ServeHTTP(w, r)
	}

	for header := range w.Header() {
		if strings.HasPrefix(header, "Access-Control-") {
			c.logger.Debug("Cors: Access-Control-* header already set", zap.String("header", header))
		}
	}

	if c.shouldHandleCors(r) {
		// Since we are handling Cors, we verified that the origin is allowed and the path matches
		c.setHeader(w, "Access-Control-Allow-Origin", origin)
		c.setHeader(w, "Vary", "Access-Control-Allow-Origin")

		c.logger.Info("Cors: Set Access-Control-Allow-Origin", zap.String("origin", origin))

		// Check for a preflight request
		if c.isPreflight(r) {
			c.logger.Info("Cors: Preflight request")

			c.setHeader(w, "Access-Control-Allow-Methods", strings.Join(c.AllowedMethods, ", "))
			c.logger.Info("Cors: Set Access-Control-Allow-Methods", zap.Strings("methods", c.AllowedMethods))

			if len(c.AllowedHeaders) > 0 {
				if contains(c.AllowedHeaders, "*") {
					c.setHeader(w, "Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
					c.logger.Info("Cors: Set Access-Control-Allow-Headers", zap.String("headers", r.Header.Get("Access-Control-Request-Headers")))
				} else {
					c.setHeader(w, "Access-Control-Allow-Headers", strings.Join(c.AllowedHeaders, ", "))
					c.logger.Info("Cors: Set Access-Control-Allow-Headers", zap.Strings("headers", c.AllowedHeaders))
				}
			}

			if c.MaxAge > 0 {
				c.logger.Info("Cors: Access-Control-Max-Age header is set to", zap.String("max_age", r.Header.Get("Access-Control-Max-Age")))

				c.setHeader(w, "Access-Control-Max-Age", fmt.Sprintf("%d", c.MaxAge))
				c.logger.Info("Cors: Set Access-Control-Max-Age", zap.Int("max_age", c.MaxAge))
			}
		} else {
			// Not a preflight request
			if len(c.ExposedHeaders) > 0 {
				c.setHeader(w, "Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ", "))
				c.logger.Info("Cors: Set Access-Control-Expose-Headers", zap.Strings("exposed_headers", c.ExposedHeaders))
			}
		}

		if c.AllowCredentials {
			c.setHeader(w, "Access-Control-Allow-Credentials", "true")
			c.logger.Info("Cors: Set Access-Control-Allow-Credentials", zap.Bool("allow_credentials", c.AllowCredentials))
		}
	}

	c.logger.Info("Cors: Calling next middleware")
	return next.ServeHTTP(w, r)
}

// replaceWriter is used to remove existing CORS headers
// and replace them with our own
type responseWriter struct {
	http.ResponseWriter
	cors *Cors
}

func (rw *responseWriter) HandleHeader(header string, value string) {
	headerExists := rw.Header().Get(header) != ""

	if headerExists && !rw.cors.OverrideExistingCors {
		rw.cors.logger.Info("Cors: Header already exists, not overriding", zap.String("header", header))
		return
	}

	if headerExists {
		rw.Header().Del(header)
	}

	rw.Header().Set(header, value)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.cors.OverrideExistingCors {
		for header, _ := range rw.ResponseWriter.Header() {
			if strings.HasPrefix(header, "Access-Control-") {
				rw.cors.logger.Info("Cors: Removing existing CORS header", zap.String("header", header))
				rw.ResponseWriter.Header().Del(header)
			}
		}
	}

	//rw.cors.set
}

// Create a function to set header values based on header name and value parameters
func (c *Cors) setHeader(w http.ResponseWriter, headerName string, headerValue string) {
	c.logger.Info("Cors: Setting header", zap.String("header_name", headerName), zap.String("header_value", headerValue))

	if c.OverrideExistingCors {
		w.Header().Set(headerName, headerValue)
		c.logger.Info("Cors: Header set", zap.String("header_name", headerName), zap.String("header_value", headerValue))
	}
}

func (c *Cors) isPreflight(r *http.Request) bool {
	c.logger.Info("Cors: Checking if preflight request")
	return r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != ""
}

func (c *Cors) shouldHandleCors(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	c.logger.Info("Cors: Checking if should handle cors", zap.String("origin", origin))

	for _, allowedOrigin := range c.AllowedOrigins {
		if allowedOrigin == "*" {
			c.logger.Info("Cors: Allowed origin is *")
			return true
		}

		// Check if the allowed origin is a regex
		c.logger.Info("Cors: Checking if allowed origin is regex")
		if strings.HasPrefix(allowedOrigin, "^") && strings.HasSuffix(allowedOrigin, "$") {
			matched, err := regexp.MatchString(allowedOrigin, origin)
			if err == nil && matched {
				c.logger.Info("Cors: Allowed origin is regex and matches", zap.String("allowed_origin", allowedOrigin), zap.String("origin", origin))
				return true
			}
		}

		if origin == allowedOrigin {
			c.logger.Info("Cors: Allowed origin matches", zap.String("allowed_origin", allowedOrigin), zap.String("origin", origin))
			return true
		}
	}

	c.logger.Info("Cors: Should not handle cors")
	return false
}

// interface guards
var (
	_ caddy.Provisioner           = (*Cors)(nil)
	_ caddy.Validator             = (*Cors)(nil)
	_ caddyhttp.MiddlewareHandler = (*Cors)(nil)
	_ caddyfile.Unmarshaler       = (*Cors)(nil)
)
