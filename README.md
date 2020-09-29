# Introduction
Small Spring service showing examples of minting signed JWTs (JSON Web Token) and validating against well known JWKs (JSON Web Key).

On startup a few EC (elliptic curves) and RSA keys are created. These are used to sign the JWT upon request. 

Validation of a JWT uses the JKU (JWK Set URL) of the JWT to lookup the public keys. These keys are indexed by kid (Key ID).

# Build and Run
Service will listen on port 8080


```
$ mvn install
....
$ java -jar target/jwks-0.0.1.jar
....
Completed initialization in 7 ms
....
```


# Endpoints

* GET /.well-known/jwks.json
Set of JWKs exposing public keys used to validate minted JWTs.

* GET /gotJwt?scope=<something>
Mint a JWT with incoming scope.

* POST /validate
Validate an incoming JWT. Pass JWT as data string.


# Examples

## Generate JWT

Validate against [jwt.io](https://jwt.io/)

```
$ JWT=$(curl -s "localhost:8080/gotJwt?scope=doit")
$ echo $JWT
eyJqa3UiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvLndlbGwta25vd25cL2p3a3MuanNvbiIsImtpZCI6IjIxMTY0MzZkLTdkNzgtNGJiNi1hODhlLThmYWMyMDAxMjY1NSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0OjgwODAiLCJzdWIiOiJnb3QgbWlsaz8iLCJzY3AiOiJkb2l0IiwiZXhwIjoxNjAxMzkxNjM1fQ.cFm5xmNyGXGlIUaapQgX9syBmHB9Fa4mrOvIC3ekV3iDjEYuqG1vovLSlflhjI91J1CriBZRQoOByt9XlyEGi3gqze8WvcVJW_BsfjX1_k4M95KEtou83XcQe7hme6Elmn3XCgQiTx-34esjLBMJ9ybt47Va2YYLk5q0P3tmQ68MCCFHicif--BSEseqpnd69XbVDbub0NJ406OxLQTuiUNP1mximvukIs33uMiROZOVfhF-GqdOl6CKkb8yq-tlfnJVErsp2_PY1rXUffWZlP74h1yoMdsZTG62Tbrkdh2SiPuzumXYNv5Rz3-HPBzwYIKSE4PsONrGorTBeX0LvQ
```

## Validate JWT

Use API to verify the signature of JWT

```
$ curl -X POST -d "$JWT" -s localhost:8080/validate
{sub=got milk?, scp=doit, iss=https://localhost:8080, exp=1601394068}%
```

Testing expired JWT

``` 
$ curl -X POST -d "$JWT" -s localhost:8080/validate
{"timestamp":"2020-09-29T15:40:00.940+0000","status":500,"error":"Internal Server Error","message":"Expired JWT","path":"/validate"}%
```


## JWKS listing

```
$ curl -s localhost:8080/.well-known/jwks.json | jq -r .
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "2116436d-7d78-4bb6-a88e-8fac20012655",
      "n": "0rNJSIuLMFAptQr4qbSBy8wqFgQKlPnu6Dvade8UKrag2zQfdaMwCseV-DZ_4QIrPL9X1NE-ytdktKiTzKBbZ6CdxxEu5uGos_F2DLBbyKGEVCFU9hhAvWp9wbPwCiGqT3WDlGQaKSwov3g5XEzRfzx3lGatY0QDs9kz5GHfdABpzRnCBNbnJcI-FY-bZTyRC7cK8kMK5rMGKj6YO4-yi04YBRcdGigKwXQv7UnAgoF6n_XH2TicKoM62RWnf0G1pHYJiu2nN0UXzs22-EvDlSXJnm6wzNSJ804_b5iuqp7hSga_1yZdNv8VDlDtUPFFbdl1wi7x7kvJjrlZKSBMJQ"
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "ae7c6725-6daa-4a1d-b06b-09eeebeb6613",
      "n": "jZ72NQ9NZ_A7WKp1O6F3GN5GD04vPu59MielatIkqRHi0SxF-Bv8vY3wY66jJIxPZflp-WRsqfqEAY5p33VxfYieSmVJGoMOATVMYXwU6sbTnm0G33-wSq-aP_JYIkGHFc2976SbfCZQAcCBZ36ulKpgE9NJhkIlaY5PvP6aLNwWmGYdsMGmiCYN8RCO1VmWuyHZUQhQ-OMlXP3XIWXbZj7Sz7sj0WUiXnAIr5LRs6HJ6gvBQIAiBYBklAGqVaNN78ifwkmgdewWq1BeNB7HweoM0J0QIJjBUH-8NWhJXXyWR0TdnooyXGskr1r-xHdAPwAeA3A-Z4PCjtor9_JAGw"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "1-N-ShxUDab3n2uu9-383prPA1DjrxliA5JzVRisixg",
      "y": "oT9KyiYx7H9l_ktp5AAiCblcoS3gq3gKP7DSKo30bOg"
    }
  ]
}

```
