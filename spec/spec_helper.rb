require 'rubygems'
require 'bundler/setup'
require 'manticore'
require 'zlib'
require 'json'
require 'rack'
require 'openssl'
require 'webrick'
require 'webrick/https'

PORT = 55441

# TLS Test Related Variables
$certdir         = File.join(File.dirname(__FILE__), 'tlspretense', 'certs')
$keystore        = File.join($certdir, 'keystore.p12')
$keystore_pass   = 'foobar'
$truststore      = File.join($certdir, 'truststore.jks')
$truststore_pass = 'foobar'

def local_server(path = "/", port = PORT)
  URI.join("http://localhost:#{port}", path).to_s
end

def read_nonblock(socket)
  buffer = ""
  loop {
    begin
      buffer << socket.read_nonblock(4096)
    rescue Errno::EAGAIN
      # Resource temporarily unavailable - read would block
      break
    end
  }
  buffer.force_encoding("UTF-8")
end

def start_server(port = PORT)
  @servers ||= {}
  @servers[port] = Thread.new {
    Net::HTTP::Server.run(port: port) do |request, stream|

      query = Rack::Utils.parse_query(request[:uri][:query].to_s)
      if query["sleep"]
        sleep(query["sleep"].to_f)
      end

      if cl = request[:headers]["Content-Length"] || request[:headers]["Transfer-Encoding"] == "chunked"
        request[:body] = read_nonblock(stream.socket)
      end

      content_type = request[:headers]["X-Content-Type"] || "text/plain"
      if request[:uri][:path] == "/auth"
        if request[:headers]["Authorization"] == "Basic dXNlcjpwYXNz"
          payload = JSON.dump(request)
          [200, {'Content-Type' => content_type, "Content-Length" => payload.length}, [payload]]
        else
          [401, {'WWW-Authenticate' => 'Basic realm="test"'}, [""]]
        end
      elsif request[:uri][:path] == "/failearly"
        # Return an invalid HTTP response
        []
      elsif match = request[:uri][:path].match(/\/cookies\/(\d)\/(\d)/)
        cookie_value = (request[:headers]["Cookie"] || "x=0").split("=").last.to_i
        if match[1].to_i == match[2].to_i
          [200, {"Set-Cookie" => "x=#{cookie_value + 1}; Path=/"}, [""]]
        else
          [301, {"Set-Cookie" => "x=#{cookie_value + 1}; Path=/", "Location" => "/cookies/#{match[1].to_i + 1}/#{match[2]}"}, [""]]
        end
      elsif request[:uri][:path] == "/proxy"
        payload = JSON.dump(request.merge(server_port: port))
        [200, {'Content-Type' => content_type, "Content-Length" => payload.length}, [payload]]
      elsif request[:uri][:path] == "/keepalive"
        payload = JSON.dump(request.merge(server_port: port))
        [200, {'Content-Type' => content_type, "Content-Length" => payload.length, "Keep-Alive" => "timeout=60"}, [payload]]
      elsif request[:headers]["X-Redirect"] && request[:uri][:path] != request[:headers]["X-Redirect"]
        [301, {"Location" => local_server( request[:headers]["X-Redirect"] )}, [""]]
      else
        if request[:headers]["Accept-Encoding"] && request[:headers]["Accept-Encoding"].match("gzip")
          out = StringIO.new('', "w")
          io = Zlib::GzipWriter.new(out, 2)
          io.write JSON.dump(request)
          io.close
          payload = out.string
          [200, {'Content-Type' => content_type, 'Content-Encoding' => "gzip", "Content-Length" => payload.length}, [payload]]
        else
          payload = JSON.dump(request)
          [200, {'Content-Type' => content_type, "Content-Length" => payload.length}, [payload]]
        end
      end
    end
  }
end

def stop_servers
  @servers.values.each(&:kill) if @servers
end

def start_ssl_server(port)
  pkey   = OpenSSL::PKey::RSA.new(File.read(File.join($certdir, 'serverkey.pem')))
  cert   = OpenSSL::X509::Certificate.new(File.read(File.join($certdir, 'servercert.pem')))
  cacert = OpenSSL::X509::Certificate.new(File.read(File.join($certdir, 'testcacert.pem')))

  @servers[port] = Thread.new {
    server = WEBrick::HTTPServer.new(
      :Port => port, :Logger => WEBrick::Log.new("/dev/null"),
      :SSLEnable => true, :SSLPrivateKey => pkey, :SSLCertificate => cert
    )

    server.mount_proc "/" do |req, res|
      res.body = "hello!"
    end

    server.start
    puts "Server started?"
  }
end

RSpec.configure do |c|
  require 'net/http/server'

  c.before(:suite) {
    @server = {}
    start_server 55441
    start_server 55442
    start_ssl_server 55444
  }

  c.after(:suite)  { stop_servers }
end

