## webtransportify

Translates WebTransport traffic to TCP socket traffic.

If you have a server with public IP address, but
- you don't have a domain name
- or your domain name resolution is banned
- or you don't have a TLS certificate

You can use this tool to securely visit your server through WebTransport tunnel.

### Features

- Auto renew self-signed WebTransport certificates (ECDSA P-256, 14 days)
- Service worker to proxy requests through WebTransport tunnel

### Usage

Run the server along with the target server.

```bash
cargo run -r -- 80
```

Certificate hash will be printed to the console.

Then visit the demo page. Set the `URL` to `<your_ip>:34433` and `Certificate Hash` to the hash printed.

Click `Connect` and you should see the target server's response.

Test the client by running the following command:

```
cargo run -r -- 127.0.0.1:34433 --client --port 34480 --sch <hash_printed>
```
