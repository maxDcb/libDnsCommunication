# libDnsCommunication

libDnsCommunication is a C++ library enabling DNS-based message tunneling. It encodes arbitrary data into DNS TXT records so a client and server can exchange messages over standard DNS infrastructure.

## Features
- UDP DNS client and server implementation.
- Message fragmentation and reassembly using JSON and hex encoding.
- Random subdomain generation and utility helpers.
- Cross-platform support for Linux and Windows.

## Building
```bash
mkdir build && cd build
cmake ..
make
```

## Running Examples
### Server
```bash
./testsDns server example.com
```
### Client
```bash
./testsDns client 8.8.8.8 example.com "hello"
```

## Testing
Unit tests are provided in the `tests` directory.
After building, run:
```bash
./utilsTest
```

## License
Specify license here.
