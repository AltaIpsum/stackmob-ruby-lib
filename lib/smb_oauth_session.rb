require "open-uri"
require "net/http"
require "net/https"
require "uri"
require "json/ext"

require 'base64'
require 'cgi'
require 'openssl'

# This monkeypatch puts your CA_FILE location in place.
# On OSX and *nix, Net::HTTP#ca_file seems to be the attribute to point 
# to your file, but Net::HTTP#ca_path may be required on other systems. 
#
# You can get around setting up your cetiticates bundle by setting 
# HTTP::Net#verify_mode to OpenSSL::SSL::VERIFY_NONE, but then you are 
# essentially just trusting that the remote host is who they say they
# are. Once you get beyond quick and dirty setup and troubleshooting, 
# you should configure your bundle. Look on Stackmob and Google if,
# like me, you are not a crypto expert. :-)
module Net
  class HTTP
    alias_method :original_use_ssl=, :use_ssl=

    def use_ssl=(flag)
      self.ca_file = ENV['CA_CERTIFICATE_FILE']
      self.verify_mode = OpenSSL::SSL::VERIFY_PEER
      self.original_use_ssl = flag
    end
  end
end

class SmbOauthSession

  attr_accessor :access_token, :mac_key, :sighost
  attr_reader :sm_user

  def api_host
    "api.stackmob.com"
  end

  # Essentially a value that must be present, but the actual value may
  # not matter. I use a JS SDK elsewhere, so I specify this user_agent.
  def user_agent
    "StackMob (JS; 0.9.2)"
  end

  def authenticated?
    @success
  end

  def set_hash_id(key)
    @hash_id = OpenSSL::Digest.hexdigest('sha1',key)
  end

  def hash_id
    @hash_id
  end

  # If you have a user-type schema other than user, specify its name as
  # the third argument.
  def login_as(username, password, user_type="user")
    uri = URI.parse("https://#{api_host}/#{user_type}/accessToken")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    request = Net::HTTP::Post.new(uri.request_uri)
    request["Accept"]="application/vnd.stackmob+json; version=#{@api_version}"
    request["X-StackMob-API-Key"] = @api_key
    request["X-StackMob-User-Agent"] = user_agent
    request.body = "username=#{CGI.escape(username)}&password=#{CGI.escape(password)}&token_type=mac"

    response = http.request(request) # To do: handle non-200 response.
    if response.code.to_i >= 500
      raise Net::HTTPServerError.new("Server Error #{response.code} from API")
    elsif response.code.to_i >= 400 && response.code.to_i != 401
      raise Net::HTTPClientError.new("Unexpected Client Response #{response.code} from API")
    end
    # Your code should handle 401 responses -- it means login failed.
    self.set_hash_id(username)
    self.initiate(response)
    return response
  end

  def initialize(opts={})
    @api_key = opts["api_key"]
    @access_token = opts["access_token"]
    @mac_key = opts["mac_key"]
    @api_version = opts["api_version"] || "0"
    @sighost = api_host
  end

  # This method is helpful if you'd like to handle a request to the 
  # Stackmob API asynchronously, e.g. with a worker or background 
  # process: pass the dumped config hash to the worker/process so it
  # can initialize a session using the same configuration.
  def dump_config
    return {
      "api_key" => @api_key,
      "access_token" => @access_token,
      "mac_key" => @mac_key,
      "api_version" => @api_version
    }
  end

  # An alternate way of initializing a new session bt taking values
  # straight out of a response to a login request.
  def initiate(http_response)
    @success = http_response.code.to_i < 400
    return unless @success

    @login_data = JSON.parse(http_response.body)
    @sm_user = @login_data['stackmob']['user']
    @access_token = @login_data["access_token"]
    @mac_key = @login_data["mac_key"]
  end

  def set_sm_user(new_user)
    return false unless @sm_user['username'] == new_user['username']
    @sm_user = new_user
  end

  def set_sm_user_attribute(attr_name, attr_value)
    attr_name = attr_name.to_s
    return false if attr_name == 'username' || attr_name == 'password'
    @sm_user[attr_name] = attr_value
  end

  # This is the master request method. It sets the correct headers,
  # including the authorization header that uses mac_key and nonce to
  # prove to Stackmob's OAuth security that you are who you say you are.
  def generate_request(rest_verb, request_uri, request_body=false, opts={})
    verb_class = Object.const_get("Net").const_get("HTTP").const_get(rest_verb.capitalize())
    request = verb_class.new(request_uri)
    request.body = JSON.dump(request_body) if request_body
    request["Accept"]="application/vnd.stackmob+json; version=#{@api_version}"
    request["X-StackMob-API-Key"] = @api_key
    request["X-StackMob-User-Agent"] = user_agent
    request["Authorization"] = get_auth_header(rest_verb.upcase(), request_uri)
    if opts[:headers]
      opts[:headers].each do |k, v|
        request[k.to_s] = v
      end
    end
    return request
  end

  # Handles get methods like GET /user/myuser
  def get_signed_request(request_uri, opts={})
    http = Net::HTTP.new(api_host, 80)
    request = generate_request("get", request_uri, false, opts)
    response = http.request(request)
    return JSON.parse(response.body), response.code.to_i
  end

  # Handles Object creation, like POST /user/newuser
  def post_signed_request(request_uri, request_params)
    http = Net::HTTP.new(api_host, 80)
    request = generate_request("post", request_uri, request_params)
    response = http.request(request)
    return JSON.parse(response.body), response.code.to_i
  end

  # Handles Append and save actions, like 
  # POST /user/myuser/things ["thingid1", "thingid2"]
  def post_related_objects(base_resource_uri, *obj_array)
    post_signed_request(base_resource_uri, obj_array.flatten)
  end
  
  # Handles Object mutation, like 
  # PUT /user/mysuser {first_name: "Worlds", last_name: "Greatest"}
  def put_signed_request(request_uri, request_params, opts={})
    http = Net::HTTP.new(api_host, 80)
    request = generate_request("put", request_uri, request_params, opts)
    response = http.request(request)
    return JSON.parse(response.body), response.code.to_i
  end

  private
  
  # Gnarly OAuth methods follow
  
  def get_auth_header(method, request_uri, opts={})
    ts = opts[:ts] || Time.now().to_i.to_s
    nonce = opts[:nonce] || "n" + rand(10 ** 10).to_s.rjust(10,'0')

    base_string = create_base_string({
      :ts => ts, :nonce => nonce,
      :method => method,
      :request_uri => request_uri,
      :host => @sighost
    })

    mac = mac_encode(base_string)
    return %Q[MAC id="#{@access_token}",ts="#{ts}",nonce="#{nonce}",mac="#{mac}"]
  end

  def create_base_string(opts)
    return [
        opts[:ts],
        opts[:nonce],
        opts[:method] || "GET",
        opts[:request_uri],
        opts[:host],
        opts[:port] || "80"
      ].join("\n") + "\n\n"
  end

  def mac_encode(base_string,opts={})
    mac_key = opts[:key] || @mac_key
    dgst = OpenSSL::Digest::Digest.new('sha1')
    hsh = OpenSSL::HMAC.digest(dgst, mac_key, base_string)
    return Base64.encode64(hsh).chomp # encode64 adds a spurious newline
  end

end
