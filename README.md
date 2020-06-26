mruby-polarssl
=========

## Description

Mbedtls (AKA PolarSSL) port for mruby, with this library your are able to use SSL/TLS and any other crypto functionality in the mruby runtime

## Features

* Set up encrypted SSL connections.

## Install
 - add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :git => 'https://github.com/WSandwitch/mruby-polarssl.git'
end
```

## Test

```ruby
ruby run_test.rb test
```

## Usage client
```ruby
socket = TCPSocket.new('polarssl.org', 443)

entropy = PolarSSL::Entropy.new
ctr_drbg = PolarSSL::CtrDrbg.new(entropy)

ssl = PolarSSL::SSL.new
ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_OPTIONAL)
ssl.set_rng(ctr_drbg)
ssl.set_socket(socket)

ssl.handshake

ssl.write("GET / HTTP/1.0\r\nHost: polarssl.org\r\n\r\n")

response = ""
while chunk = ssl.read(1024)
  response << chunk
end

puts response

ssl.close_notify

socket.close

ssl.close
```

## Usage server
```ruby
entropy = PolarSSL::Entropy.new
ctr_drbg = PolarSSL::CtrDrbg.new(entropy)

x509 = PolarSSL::X509.new
puts x509.parse(File.open("serv/server101.mycloud.pem","r"){|f| f.read})

ca = PolarSSL::X509.new
puts ca.parse(File.open("serv/rootCA.crt","r"){|f| f.read})

pkey = PolarSSL::PK.new(File.open("serv/rootCA.key","r"){|f| f.read})

conf = PolarSSL::Conf.new(PolarSSL::Conf::SSL_IS_SERVER)
conf.set_authmode(PolarSSL::Conf::SSL_VERIFY_NONE)
conf.set_rng(ctr_drbg)
conf.set_chain(x509)
conf.set_sert(ca, pkey)


ssl = PolarSSL::SSL.new
ssl.setup(conf)

tcp = TCPServer.new("0.0.0.0", 3000)

loop do
  ssl.reset 
  io = BasicSocket.for_fd(tcp.sysaccept)
  io.setsockopt(Socket::SOL_SOCKET, Socket::SO_NOSIGPIPE, true) if Socket.const_defined? :SO_NOSIGPIPE
  puts "got connection"
  ssl.set_socket(io)
  
  puts (ssl.handshake rescue "false")

  begin
	p ssl.read(1024)
	ssl.write("hello")
  rescue => e  
  p e
	raise 'Connection reset by peer' if io.closed?
  ensure
    sleep(1)
	ssl.close_notify
	io.close rescue nil
	GC.start 
  end
end

```


### Encrypting data

The `PolarSSL::Cipher` class lets you encrypt data with a wide range of
encryption standards DES-CBC, DES-ECB, DES3-CBC and DES3-ECB.

This sample encrypts a given plaintext with DES-ECB:

```ruby
cipher = PolarSSL::Cipher.new("DES-ECB")
cipher.encrypt
cipher.key = "0123456789ABCDEF"
cipher.update("1111111111111111")
# => "17668DFC7292532D"
```

## DEBUG

Add flag `MRUBY_MBEDTLS_DEBUG_C` on mrbgem.rake to enable mbedtls debugs via stdout, example:

```
-  spec.cc.flags << '-D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement'
+  spec.cc.flags << '-D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement -DMRUBY_MBEDTLS_DEBUG_C'
```

If customized display is required check `my_debug_func()`.

## License

Under Apache 2.0 license, same as mbedtls license

```
mruby-polarssl - A mruby extension for using mbedtls (AKA PolarSSL).
Copyright (C) 20139  Luis Silva
```
