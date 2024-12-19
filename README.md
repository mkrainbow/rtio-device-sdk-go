# RTIO-DEVICE-SDK-GO

设备也是服务资源的提供者，RTIO采取REST-Like模型，使设备端开发高效和有趣。

"RTIO-DEVICE-SDK-GO"为Golang版的设备端SDK，用于连接RTIO服务。

## 运行Demo

目前仅在Linux环境下测试。

### RTIO服务端运行

#### 通过源码运行

- Golang：版本1.21.0或以上。
- GNU Make：建议版本4.3或以上。

```sh
$ git clone https://github.com/mkrainbow/rtio.git
$ cd rtio/
$ make
$ ls ./out/
examples  rtio
```

通过以下命令运行服务，可通过`./out/rtio -h`查看帮助。

```sh
$ ./out/rtio -disable.deviceverify -disable.hubconfiger -log.level info
2024-12-19 17:07:14.198 INF rtio starting ...
```

#### 通过docker运行

准备中。

#### 设备端Demo演示

```sh
$ git clone https://github.com/mkrainbow/rtio-device-sdk-go.git
$ mkdir -p out 
$ go build -o out/ github.com/mkrainbow/rtio-device-sdk-go/...
$ make
$ ls out/
simple_device  simple_device_copost_to_server  simple_device_obget  simple_device_tls
```

运行`simple_device`。

```sh
./out/simple_device
```

打开另一终端运行`curl`模拟请求到设备。

```sh
$  curl http://localhost:17917/cfa09baa-4913-4ad7-a936-3e26f9671b09 -d '{"method":"copost", "uri":"/rainbow","id":12667,"data":"aGVsbG8="}'
{"id":12667,"fid":0,"code":"OK","data":"d29ybGQ="}
```

其中，"aGVsbG8="为"hello"的base64编码，"d29ybGQ="为"world"的base64编码。可通过以下命令在终端里编解码。

```sh
$ echo -n "hello" | base64       # Encode
aGVsbG8=
$ echo -n "d29ybGQ=" | base64 -d # Decode
world
```

设备端输出：

```sh
$ ./out/simple_device
2024/12/19 17:24:50 received [hello] and reply [world]
```

## 集成SDK

添加库：

```sh  
go get github.com/mkrainbow/rtio-device-sdk-go
```

使用库：

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


```

## 错误码

