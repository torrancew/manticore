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

def start_ssl_server(port, client_auth=false)
  if client_auth
    server_name = 'authserver'
  else
    server_name = 'server'
  end

  pkey   = OpenSSL::PKey::RSA.new(File.read(File.join($certdir, "#{server_name}key.pem")))
  cert   = OpenSSL::X509::Certificate.new(File.read(File.join($certdir, "#{server_name}cert.pem")))
  cacert = OpenSSL::X509::Certificate.new(File.read(File.join($certdir, 'testcacert.pem')))

  @servers[port] = Thread.new {
    config = {
      :Port => port, :Logger => WEBrick::Log.new($stderr),
      :SSLEnable => true, :SSLPrivateKey => pkey, :SSLCertificate => cert,
    }
    if client_auth
      config.merge!({
        :SSLVerifyClient => OpenSSL::SSL::VERIFY_NONE|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT,
        :SSLClientCA => cacert
      })
    end

    server = WEBrick::HTTPServer.new(config)

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
    start_ssl_server 55443, true
  }

  c.after(:suite)  { stop_servers }
end

