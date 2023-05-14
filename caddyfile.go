package caddy_cors

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Cors{})
	httpcaddyfile.RegisterHandlerDirective("cors", parseCaddyfile)
}

func (Cors) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cors",
		New: func() caddy.Module { return new(Cors) },
	}
}

func (c *Cors) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		if len(args) > 0 {
			c.AllowedOrigins = args
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "allowed_origins":
				c.AllowedOrigins = d.RemainingArgs()

			case "override_existing_cors":
				if d.NextArg() {
					c.OverrideExistingCors = d.Val() == "true"
				} else {
					return d.ArgErr()
				}

			case "allowed_methods":
				c.AllowedMethods = d.RemainingArgs()

			case "allow_credentials":
				if d.NextArg() {
					c.AllowCredentials = d.Val() == "true"
				} else {
					return d.ArgErr()
				}

			case "max_age":
				if d.NextArg() {
					maxAge, err := strconv.Atoi(d.Val())
					if err != nil {
						return d.Errf("invalid max_age value: %v", err)
					}
					c.MaxAge = maxAge
				} else {
					return d.ArgErr()
				}

			case "allowed_headers":
				c.AllowedHeaders = d.RemainingArgs()

			case "exposed_headers":
				c.ExposedHeaders = d.RemainingArgs()

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var cors Cors
	err := cors.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return cors, nil
}
