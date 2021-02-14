# Development Requirements

### Protoc compiler

Download and install using the following commands:

```
curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/protoc-3.14.0-linux-x86_64.zip
unzip protoc-3.14.0-linux-x86_64.zip -d protoc3
sudo cp -r protoc3/bin/* /usr/local/bin/
sudo cp -r protoc3/include/* /usr/local/include/
sudo chown $USER /usr/local/bin/protoc
protoc
```

### Protobuf message compilation for Golang

Installation:


```
go install google.golang.org/protobuf/cmd/protoc-gen-go
```

Compile to go:

```
protoc --go_out=. *.proto
```

### Protobuf message compilation for Javascript

```
cd filefilego
protoc --proto_path=node --js_out=import_style=commonjs,binary:build messages.proto
```