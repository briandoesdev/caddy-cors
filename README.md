# Caddy CORS Module

Caddy CORS is built to allow easy control over cross origin resource sharing from your Caddy configuration. It based off of the [cors](https://github.com/captncraig/cors) module created by [captncraig](https://github.com/captncraig).

### Directive Syntax
```
cors [<matcher>] [allowed_origins: []string] {
  override_existing_cors: bool
  allowed_methods:        []string
  allow_credentials:      bool
  max_age:                int
  allowed_headers:        []string
  exposed_headers:        []string
}
```

### Defaults
These are the default values of the Cors directive if left unset.
- path: "/"
- allowed_origins: "*"
- override_existing_cors: false
- allowed_methods: "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
- allow_credentials: false
- max_age: 5 seconds
- allowed_headers: empty
- exposed_headers: empty

## How to install
> Install instructions here

## How to use
> Usage instructions here

## Example Caddyfile
```
 Example caddyfile here
```