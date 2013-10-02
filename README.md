# Ruby StackMob API Library

This is a Ruby library for making authentication and RESTful resource
HTTP calls to the Stackmob API. [Stackmob](http://www.stackmob.com) is 
a Platform-as-a-Service provider that we use at 
[AltaIpsum](http://www.altaipsum.com) to back our client-side HTML5 app
and, coming soon, native smartphone apps. Stackmob provides SDKs for 
Javascript, iOS, and Android, and it exposes a RESTful API as well.
This project was developed to allow Ruby applications to access app
data at Stackmob as well.

## HOWTO

The file `lib/smb_oauth_session.rb` is the only file you need.
`require` or `use` it into your Ruby code to be able to instantiate a 
`SmbOauthSession` object. I've commented the code to try to make it
clear which methods do what.

### Examples 

I've included an example Sinatra app that you should be able to set up
and run against your own Stackmob app's data. It will let you log in as
one of your app's users and display the contents of the user object
returned. You should be able to add GET, POST, and PUT methods. 

If you'd like more information about Sinatra, a nice lightweight Ruby 
web framework, [the Sinatra project](http://www.sinatrarb.com/) is 
well documented.

I like to run Sinatra with [foreman](https://github.com/ddollar/foreman)
and Procfiles. There's a sample Procfile for the example app along with 
a sample .env file for specifying ENV variables when running the app
locally.

### Net::HTTP

I know a lot of people don't like Net::HTTP or prefer another HTTP
library. I encourage you to adapt the library to whatever alternative
you prefer. I like having as few dependencies as possible, though, and
Net::HTTP comes with Ruby.

## Authors

### Hacked together by 

Michael Harrison, michael@altaipsum.com

### Pull requests welcome!
