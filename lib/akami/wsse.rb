require "base64"
require "digest/sha1"
require "akami/core_ext/hash"
require "akami/xpath_helper"
require "akami/c14n_helper"
require "time"
require "gyoku"

require "akami/wsse/verify_signature"
require "akami/wsse/signature"

module Akami

  # = Akami::WSSE
  #
  # Building Web Service Security.
  class WSSE

    # Namespace for WS Security Secext.
    WSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

    # Namespace for WS Security Utility.
    WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

    # PasswordText URI.
    PASSWORD_TEXT_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"

    # PasswordDigest URI.
    PASSWORD_DIGEST_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"

    BASE64_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

    # Returns a value from the WSSE Hash.
    def [](key)
      hash[key]
    end

    # Sets a value on the WSSE Hash.
    def []=(key, value)
      hash[key] = value
    end

    # Sets authentication credentials for a wsse:UsernameToken header.
    # Also accepts whether to use WSSE digest authentication.
    def credentials(username, password, digest = false)
      self.username = username
      self.password = password
      self.digest = digest
    end

    attr_accessor :username, :password, :created_at, :expires_at, :signature, :verify_response

    def sign_with=(klass)
      @signature = klass
    end

    def signature?
      !!@signature
    end

    # Returns whether to use WSSE digest. Defaults to +false+.
    def digest?
      !!@digest
    end

    attr_writer :digest

    # Returns whether to generate a wsse:UsernameToken header.
    def username_token?
      username && password
    end

    # Returns whether to generate a wsu:Timestamp header.
    def timestamp?
      created_at || expires_at || @wsu_timestamp
    end

    # Sets whether to generate a wsu:Timestamp header.
    def timestamp=(timestamp)
      @wsu_timestamp = timestamp
    end

    # Hook for Soap::XML that allows us to add attributes to the env:Body tag
    def body_attributes
      if signature?
        signature.body_attributes
      else
        {}
      end
    end

    # Returns the XML for a WSSE header.
    def to_xml
      xml = hash

      if signature? and signature.have_document?
        xml.merge!(wsse_signature)
      elsif username_token?
        xml.merge!(wsse_username_token)
      end

      if timestamp?
        xml.merge!(wsu_timestamp) do |key, v1, v2|
          v1.merge!(v2) do |key, v1, v2|
            if v1.is_a?(Hash) && v2.is_a?(Hash)
              v1.merge!(v2)
            end
          end
        end
        unless xml['wsse:Security'][:order!].nil?
          xml['wsse:Security'][:order!] << 'wsu:Timestamp'
        end
      end

      Gyoku.xml xml
    end
  private

    # Returns a Hash containing wsse:UsernameToken details.
    def wsse_username_token
      if digest?
        token = security_hash :wsse, "UsernameToken",
          "wsse:Username" => username,
          "wsse:Nonce" => Base64.encode64(nonce).chomp,
          "wsu:Created" => timestamp,
          "wsse:Password" => digest_password,
          :attributes! => { "wsse:Password" => { "Type" => PASSWORD_DIGEST_URI },  "wsse:Nonce" => { "EncodingType" => BASE64_URI } }
        # clear the nonce after each use
        @nonce = nil
      else
        token = security_hash :wsse, "UsernameToken",
          "wsse:Username" => username,
          "wsse:Password" => password,
          :attributes! => { "wsse:Password" => { "Type" => PASSWORD_TEXT_URI } }
      end
      token
    end

    def wsse_signature
      signature_hash = signature.to_token

      # First key/value is tag/hash
      tag, hash = signature_hash.shift

      security_hash nil, tag, hash, signature_hash
    end

    # Returns a Hash containing wsu:Timestamp details.
    def wsu_timestamp
      security_hash :wsu, "Timestamp",
        "wsu:Created" => (created_at || Time.now).utc.xmlschema,
        "wsu:Expires" => (expires_at || (created_at || Time.now) + 60).utc.xmlschema
    end

    # Returns a Hash containing wsse/wsu Security details for a given
    # +namespace+, +tag+ and +hash+.
    def security_hash(namespace, tag, hash, extra_info = {})
      key = [namespace, tag].compact.join(":")

      sec_hash = {
        "wsse:Security" => {
          key => hash
        },
        :attributes! => { "wsse:Security" => { "xmlns:wsse" => WSE_NAMESPACE } }
      }

      unless extra_info.empty?
        sec_hash["wsse:Security"].merge!(extra_info)
      end

      if signature?
        sec_hash[:attributes!].merge!("soapenv:mustUnderstand" => "1")
      else
        sec_hash["wsse:Security"].merge!(:attributes! => { key => { "wsu:Id" => "#{tag}-#{count}", "xmlns:wsu" => WSU_NAMESPACE } })
      end

      sec_hash
    end

    # Returns the WSSE password, encrypted for digest authentication.
    def digest_password
      token = nonce + timestamp + password
      Base64.encode64(Digest::SHA1.digest(token)).chomp!
    end

    # Returns a WSSE nonce.
    def nonce
      @nonce ||= Digest::SHA1.hexdigest random_string + timestamp
    end

    # Returns a random String of 100 characters.
    def random_string
      (0...100).map { ("a".."z").to_a[rand(26)] }.join
    end

    # Returns a WSSE timestamp.
    def timestamp
      @timestamp ||= Time.now.utc.xmlschema
    end

    # Returns a new number with every call.
    def count
      @count ||= 0
      @count += 1
    end

    # Returns a memoized and autovivificating Hash.
    def hash
      @hash ||= Hash.new { |h, k| h[k] = Hash.new(&h.default_proc) }
    end

  end
end
