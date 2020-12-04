# bash_tls
A minimal TLS 1.2 implementation in a pure Bash script

bash_tls implements TLS well enough to make a simple HTTPS request to most web servers.

## Usage
`./bash_tls.sh [https://website.com/path/to/file]`  
If a URL is not given, defaults to `https://www.google.com/robots.txt`.

## Features
* Supports a single cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256
  * RSA key exchange
  * HMAC-SHA256 as pseudorandom function
  * AES in GCM mode for encryption
* Supports Server Name Indication

## Missing
* Only supports RSA certificates
* Does not validate certificate chain

## Dependencies
bash_tls depends only on the following software:
* bash 4.3+ compiled with `--enable-net-redirections`
* GNU bc (for doing RSA calculations)
* sha256sum (from Linux coreutils) or shasum (on Mac)

## Performance
Don't ask.
