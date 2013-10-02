require 'date'
require 'sinatra/base'
require 'haml'

# I'm using the Warden gem to manage authenticated sessions
require 'warden'

# I'm storing session information in memcache with help from Dalli gem
# If you host your app on heroku, you an use their memcachier plugin,
# as demonstrated in the development and production environment
# configuration blocks below.
require 'dalli'
require 'memcachier'

# The API library
require '../../lib/smb_oauth_session'

class ExampleApp < Sinatra::Base

  set :haml, :format => :html5
  set :port, ENV['PORT']

  enable :logging

  # Prefer keeping sensitive config strings in ENV vars over sticking
  # them in code.
  set :smb_api_key, ENV["STACKMOB_API_KEY"]
  set :cookie_secret, ENV['COOKIE_SECRET']

  configure :local do
    # Memcache stores StackMob session info
    set :cache, Dalli::Client.new('localhost:11211')
    set :api_version, "0"
  end

  configure :development do
    # Memcachier handles client config on heroku
    set :cache, Dalli::Client.new
    set :api_version, "0"
  end

  configure :production do
    # Memcachier handles client config on heroku
    set :cache, Dalli::Client.new
    set :api_version, "1"
  end

  def open_oauth_session
    return SmbOauthSession.new("api_key" => settings.smb_api_key,
                               "api_version" => settings.api_version)
  end

  get('/') do
    session[:test] = "String stored in session"
    haml :index
  end

  get '/login' do
    haml :login, :locals => { :alert => false, :debug => settings }
  end

  get "/logout" do
    warden_handler.logout
    redirect '/login'
  end

  get '/test' do
    "Session Test: #{session[:test]}"
  end

  get '/account' do
    check_authentication
    haml :account, :locals => {
      :username => current_username,
      :user => current_user_session.sm_user }
  end

  def update_session_user(new_sm_user)
    current_user_session.set_sm_user(new_sm_user)
    warden_handler.set_user(current_user_session)
    return self
  end


  ## Session Protection
  #
  # I'm using Warden because I've used it with Devise in Ruby on Rails
  # applications. There are probably a lot of other ways to enforce
  # session authentication

  use Rack::Session::Cookie, :key => 'rack.session',
   :path => '/',
   :expire_after => 900, # In seconds
   :secret => settings.cookie_secret

  post "/session" do
    warden_handler.authenticate!
    if warden_handler.authenticated?
      redirect "/account"
    end
  end

  post "/unauthenticated" do
    haml :login, :locals => {
        :alert => "Login failed. Please try again." }
  end

  use Warden::Manager do |manager|
    use Rack::Logger
    manager.default_strategies :password
    manager.failure_app = ExampleApp

    manager.serialize_into_session do |smb_session|
      # 600 = 10 minutes before cached session info times out.
      ExampleApp.cache.set(smb_session.hash_id, smb_session, 600)
      smb_session.hash_id
    end
    manager.serialize_from_session do |hash_id|
      ExampleApp.cache.fetch(hash_id)
    end
  end

  Warden::Manager.before_failure do |env,opts|
    env['REQUEST_METHOD'] = 'POST'
  end

  Warden::Strategies.add(:password) do
    # Hint: To log to strerr within Warden methods, use request.logger
    def valid?
      params["username"] || params["password"]
    end

    def authenticate!
      api_key = ExampleApp.smb_api_key
      api_version = ExampleApp.api_version
      cache = ExampleApp.cache
      smb_session = SmbOauthSession.new("api_key" => api_key, "api_version" => api_version)
      smb_session.login_as(params["username"], params["password"])
      if smb_session.authenticated?
        # 600 = 10 minutes before session times out.
        cache.set(smb_session.hash_id, smb_session, 600)
        success!(smb_session)
      else
        fail!("Could not log in")
      end
    end
  end

  def warden_handler
    env['warden']
  end

  def check_authentication
    redirect '/login' unless warden_handler.authenticated?
  end

  def current_user_session
    warden_handler.user
  end

  def current_user
    current_user_session.sm_user unless current_user_session.nil?
  end

  def current_username
    current_user_session.sm_user['username']
  end

  run! if __FILE__ == $0

end
