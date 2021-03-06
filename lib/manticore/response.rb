module Manticore
  # Implementation of {http://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/client/ResponseHandler.html ResponseHandler} which serves
  # as a Ruby proxy for HTTPClient responses.
  #
  # @!attribute [r] headers
  #   @return [Hash] Headers from this response
  # @!attribute [r] code
  #   @return [Integer] Response code from this response
  # @!attribute [r] context
  #   @return [HttpContext] Context associated with this request/response
  # @!attribute [r] callback_result
  #   @return Value returned from any given on_success/response block
  class Response
    include_package "org.apache.http.client"
    include_package "org.apache.http.util"
    include_package "org.apache.http.protocol"
    java_import "org.apache.http.client.protocol.HttpClientContext"
    java_import 'java.util.concurrent.Callable'

    include ResponseHandler
    include Callable

    attr_reader :context, :request, :callback_result, :called

    # Creates a new Response
    #
    # @param  request            [HttpRequestBase] The underlying request object
    # @param  context            [HttpContext] The underlying HttpContext
    def initialize(client, request, context, &block)
      @client  = client
      @request = request
      @context = context
      @handlers = {
        success:   block || Proc.new {|resp| resp.body },
        failure:   Proc.new {|ex| raise ex },
        cancelled: Proc.new {},
        complete:  []
      }
    end

    # Implementation of Callable#call
    # Used by Manticore::Client to invoke the request tied to this response. Users should never call this directly.
    def call
      raise "Already called" if @called
      @called = true
      begin
        @client.execute @request, self, @context
        execute_complete
        return self
      rescue Java::JavaNet::SocketTimeoutException, Java::OrgApacheHttpConn::ConnectTimeoutException => e
        ex = Manticore::Timeout.new(e.get_cause)
      rescue Java::JavaNet::SocketException => e
        ex = Manticore::SocketException.new(e.get_cause)
      rescue Java::OrgApacheHttpClient::ClientProtocolException, Java::JavaxNetSsl::SSLHandshakeException, Java::OrgApacheHttpConn::HttpHostConnectException,
             Java::OrgApacheHttp::NoHttpResponseException, Java::OrgApacheHttp::ConnectionClosedException => e
        ex = Manticore::ClientProtocolException.new(e.get_cause)
      rescue Java::JavaNet::UnknownHostException => e
        ex = Manticore::ResolutionFailure.new(e.get_cause)
      end
      @exception = ex
      @handlers[:failure].call ex
      execute_complete
    end

    def fire_and_forget
      @client.executor.submit self
    end

    # Fetch the final resolved URL for this response. Will call the request if it has not been called yet.
    #
    # @return [String]
    def final_url
      call_once
      last_request = context.get_attribute ExecutionContext.HTTP_REQUEST
      last_host    = context.get_attribute ExecutionContext.HTTP_TARGET_HOST
      host         = last_host.to_uri
      url          = last_request.get_uri
      URI.join(host, url.to_s)
    end

    # Fetch the body content of this response. Will call the request if it has not been called yet.
    # This fetches the input stream in Ruby; this isn't optimal, but it's faster than
    # fetching the whole thing in Java then UTF-8 encoding it all into a giant Ruby string.
    #
    # This permits for streaming response bodies, as well.
    #
    # @example Streaming response
    #
    #     client.get("http://example.com/resource").on_success do |response|
    #       response.body do |chunk|
    #         # Do something with chunk, which is a parsed portion of the returned body
    #       end
    #     end
    #
    # @return [String] Reponse body
    def body(&block)
      call_once
      @body ||= begin
        if entity = @response.get_entity
          EntityConverter.new.read_entity(entity, &block)
        end
      rescue Java::JavaIo::IOException, Java::JavaNet::SocketException, IOError => e
        raise StreamClosedException.new("Could not read from stream: #{e.message}")
      # ensure
      #   @request.release_connection
      end
    end
    alias_method :read_body, :body

    # Returns true if this response has been called (requested and populated) yet
    def called?
      !!@called
    end

    # Return a hash of headers from this response. Will call the request if it has not been called yet.
    #
    # @return [Array<string, obj>] Hash of headers. Keys will be lower-case.
    def headers
      call_once
      @headers
    end

    # Return the response code from this request as an integer. Will call the request if it has not been called yet.
    #
    # @return [Integer] The response code
    def code
      call_once
      @code
    end

    # Returns the length of the response body. Returns -1 if content-length is not present in the response.
    #
    # @return [Integer]
    def length
      (headers["content-length"] || -1).to_i
    end

    # Returns an array of {Manticore::Cookie Cookies} associated with this request's execution context
    #
    # @return [Array<Manticore::Cookie>]
    def cookies
      call_once
      @cookies ||= begin
        @context.get_cookie_store.get_cookies.inject({}) do |all, java_cookie|
          c = Cookie.from_java(java_cookie)
          all[c.name] ||= []
          all[c.name] << c
          all
        end
      end
    end

    # Set handler for success responses
    # @param block Proc which will be invoked on a successful response. Block will receive |response, request|
    #
    # @return self
    def on_success(&block)
      @handlers[:success] = block
      self
    end
    alias_method :success, :on_success

    # Set handler for failure responses
    # @param block Proc which will be invoked on a on a failed response. Block will receive an exception object.
    #
    # @return self
    def on_failure(&block)
      @handlers[:failure] = block
      self
    end
    alias_method :failure, :on_failure
    alias_method :fail,    :on_failure

    # Set handler for cancelled requests
    # @param block Proc which will be invoked on a on a cancelled response.
    #
    # @return self
    def on_cancelled(&block)
      @handlers[:cancelled] = block
      self
    end
    alias_method :cancelled,       :on_cancelled
    alias_method :cancellation,    :on_cancelled
    alias_method :on_cancellation, :on_cancelled

    # Set handler for cancelled requests
    # @param block Proc which will be invoked on a on a cancelled response.
    #
    # @return self
    def on_complete(&block)
      @handlers[:complete] = Array(@handlers[:complete]).compact + [block]
      self
    end
    alias_method :complete,     :on_complete
    alias_method :completed,    :on_complete
    alias_method :on_completed, :on_complete

    def times_retried
      @context.get_attribute("retryCount") || 0
    end

    private

    # Implementation of {http://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/client/ResponseHandler.html#handleResponse(org.apache.http.HttpResponse) ResponseHandler#handleResponse}
    # @param  response [Response] The underlying Java Response object
    def handleResponse(response)
      @response        = response
      @code            = response.get_status_line.get_status_code
      @headers         = Hash[* response.get_all_headers.flat_map {|h| [h.get_name.downcase, h.get_value]} ]
      @callback_result = @handlers[:success].call(self)
      nil
    end

    def call_once
      call unless called?
      @called = true
    end

    def execute_complete
      @handlers[:complete].each &:call
    end
  end
end