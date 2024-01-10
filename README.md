Akami
=====

Building Web Service Security.

[![Ruby](https://github.com/savonrb/akami/actions/workflows/ci.yml/badge.svg)](https://github.com/savonrb/akami/actions/workflows/ci.yml)

The XML namespaces used by this gem begin with http://docs.oasis-open.org/wss/2004/01/. That URL has PDF documentation of "Web Services Security UsernameToken Profile 1.0" and "Web Services Security: SOAP Message Security 1.0 (WS-Security 2004)".

To place this in a historical context [Wikipedia on WS-Security](https://en.wikipedia.org/wiki/WS-Security) mentions "wsse" namespace prefix in its [History section](https://en.wikipedia.org/wiki/WS-Security#History).


Installation
------------

Akami is available through [Rubygems](http://rubygems.org/gems/akami) and can be installed via:

```
$ gem install akami
```


Getting started
---------------

``` ruby
wsse = Akami.wsse
```

Set the credentials for `wsse:UsernameToken` basic auth:

``` ruby
wsse.credentials "username", "password"
```

Set the credentials for `wsse:UsernameToken` digest auth:

``` ruby
wsse.credentials "username", "password", :digest
```

Enable `wsu:Timestamp` headers. `wsu:Created` is automatically set to `Time.now`
and `wsu:Expires` is set to `Time.now + 60`:

``` ruby
wsse.timestamp = true
```

Manually specify the values for `wsu:Created` and `wsu:Expires`:

``` ruby
wsse.created_at = Time.now
wsse.expires_at = Time.now + 60
```

Akami is based on an autovivificating Hash. So if you need to add custom tags, you can add them.

``` ruby
wsse["wsse:Security"]["wsse:UsernameToken"] = { "Organization" => "ACME" }
```

When generating the XML for the request, this Hash will be merged with another Hash containing
all the default tags and values.  
This way you might dig into some code, but then you can even overwrite the default values.

``` ruby
wsse.to_xml
```
