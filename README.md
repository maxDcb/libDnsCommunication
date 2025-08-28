# libDnsCommunication

libDnsCommunication is a C++ library enabling DNS-based message tunneling.  
It encodes arbitrary data into DNS TXT records so a client and server can exchange messages over standard DNS infrastructure.

## Features
- UDP DNS client and server implementation.
- Message fragmentation and reassembly using JSON and hex encoding.
- Random subdomain generation and utility helpers.
- Cross-platform support for Linux and Windows.

## Building
```bash
# linux
mkdir build && cd build
cmake ..
make

#windows
mkdir build && cd build
cmake ..
msbuild Dnscommunication.sln
````

## Running Examples

### Functional Test

A dedicated binary `fonctionalTest` is provided to validate client/server communication.

#### Usage

**Server mode**

```bash
./fonctionalTest server --domain ns.example.com [--port 53] [--test-msg "text"] [--run-seconds 5]
```

**Client mode**

```bash
./fonctionalTest client --dns <resolver_ip> --host ns.example.com --send "text" [--timeout 5] [--expect "expected-reply"]
```

#### Local Testing

You can test locally without a real DNS server:

1. Pick a fake domain (e.g., `test.dnstestdomain`).
2. Add it to `/etc/hosts` pointing to `127.0.0.1`:

   ```
   127.0.0.1   test.dnstestdomain
   ```
3. Run the server:

   ```bash
   ./fonctionalTest server --domain test.dnstestdomain --port 5353 --run-seconds 60 --test-msg "hello"
   ```
4. Run the client, pointing to localhost (`127.0.0.1`):

   ```bash
   ./fonctionalTest client --dns 127.0.0.1 --host test.dnstestdomain --send "hello" --expect "hello" --port 5353
   ```

If the message is received correctly, the client will print `EXPECTATION OK` and exit with code `0`.

This setup is useful for **CI pipelines** or quick validation without relying on external resolvers.

---

## Unit Testing

Unit tests are provided in the `tests` directory. After building, run:

```bash
./utilsTest
```

## License
MIT
