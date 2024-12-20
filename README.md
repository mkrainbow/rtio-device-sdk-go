# RTIO-DEVICE-SDK-GO

> English | [简体中文](./README-CN.md)  
> The author's native language is Chinese. This document is translated using AI.


RTIO-DEVICE-SDK-GO is a Go version of the device-side SDK for connecting to the RTIO service.

Devices are also resource providers in RTIO. RTIO uses a REST-Like model, making device-side development efficient and enjoyable.

## Run Demo

Currently tested only on Linux environments.

### RTIO Server Setup

#### Run RTIO from Source

Tools：

- Golang: Version 1.21.0 or higher.
- GNU Make: Recommended version 4.3 or higher.
- Git.

Clone source code：

```sh
$ git clone https://github.com/mkrainbow/rtio.git
$ cd rtio/
$ make
$ ls ./out/
examples  rtio
```

To run the service, use the following command. You can view the help with `./out/rtio -h`.

```sh
$ ./out/rtio -disable.deviceverify -disable.hubconfiger -log.level info
2024-12-19 17:07:14.198 INF rtio starting ...
```

#### Run RTIO via Docker

Coming soon.

#### Run Device Demo

```sh
$ git clone https://github.com/mkrainbow/rtio-device-sdk-go.git
$ mkdir -p out 
$ go build -o out/ github.com/mkrainbow/rtio-device-sdk-go/...
$ make
$ ls out/
simple_device  simple_device_copost_to_server  simple_device_obget  simple_device_tls
```

run `simple_device`。

```sh
./out/simple_device
```

Open another terminal and use `curl` to request the device's URI `/rainbow` through the RTIO service, sending the string "hello" to the device, which responds with "world".

```sh
$  curl http://localhost:17917/cfa09baa-4913-4ad7-a936-3e26f9671b09 -d '{"method":"copost", "uri":"/rainbow","id":12667,"data":"aGVsbG8="}'
{"id":12667,"fid":0,"code":"OK","data":"d29ybGQ="}
```

Here, "aGVsbG8=" is the base64 encoding of "hello", and "d29ybGQ=" is the base64 encoding of "world". You can encode and decode in the terminal using the following commands

```sh
$ echo -n "hello" | base64       # Encode
aGVsbG8=
$ echo -n "d29ybGQ=" | base64 -d # Decode
world
```

Output on the device side：

```sh
$ ./out/simple_device
received [hello] and reply [world]
```

## SDK Integration

Add library：

```sh  
go get github.com/mkrainbow/rtio-device-sdk-go
```

Integrate the rtio-device-sdk-go library：

```go
import (
    "github.com/mkrainbow/rtio-device-sdk-go/rtio"
)

func main() {

    // Connect to rtio service.
    session, err := rtio.Connect(context.Background(), *deviceID, *deviceSecret, *serverAddr)

    // ...
    
    // Register handler for URI.
    session.RegisterPostHandler("/rainbow", func(req []byte) ([]byte, error) {
        log.Printf("received [%s] and reply [world]", string(req))
        return []byte("world"), nil
    })

    // Session serve in the background.
    session.Serve(context.Background())

    // Do other things.
    time.Sleep(time.Hour * 8760)
}
```

## API列表

```go
// Connect establishes a connection to a server with the provided device credentials.
func Connect(ctx context.Context, deviceID, deviceSecret, serverAddr string) (*DeviceSession, error) 
// ConnectWithLocalAddr establishes a connection with a specified local address. Usually for testing.
func ConnectWithLocalAddr(ctx context.Context, deviceID, deviceSecret, localAddr, serverAddr string) (*DeviceSession, error) 
// ConnectWithTLS establishes a TLS-encrypted connection to the server.
func ConnectWithTLS(ctx context.Context, deviceID, deviceSecret, serverAddr, caFile string) (*DeviceSession, error) 
// ConnectWithTLSSkipVerify establishes a TLS-encrypted connection, skipping certificate verification.
func ConnectWithTLSSkipVerify(ctx context.Context, deviceID, deviceSecret, serverAddr string) (*DeviceSession, error) 

// SetLogConfigs sets the logging configuration (text, json) and log Level (debug, info, warn, error)
func SetLogConfigs(format, level string) 

// SetHeartbeatSeconds sets the heartbeat interval in seconds for the device session.
func (*DeviceSession) SetHeartbeatSeconds(n uint16) 
// Serve starts the device session and serves requests in background until the context is canceled.
func (*DeviceSession) Serve(ctx context.Context) 
// RegisterCoPostHandler registers a handler for CoPOST requests to the specified URI.Not Thread-safe.
func (*DeviceSession) RegisterCoPostHandler(uri string, handler func(req []byte) ([]byte, error)) error 
// RegisterObGetHandler registers a handler for ObGET requests to the specified URI.Not Thread-safe.
func (*DeviceSession) RegisterObGetHandler(uri string, handler func(ctx context.Context, req []byte) (<-chan []byte, error)) error 
// CoPost Sends a CoPost request to the specified URI with the given payload and timeout.
func (*DeviceSession) CoPost(ctx context.Context, uri string, Req []byte, timeout time.Duration) ([]byte, error) 

```
