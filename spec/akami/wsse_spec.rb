require 'spec_helper'
require 'base64'
require 'nokogiri'

describe Akami do
  let(:wsse) { Akami.wsse }

  it "contains the namespace for WS Security Secext" do
    expect(Akami::WSSE::WSE_NAMESPACE).to eq(
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    )
  end

  it "contains the namespace for WS Security Utility" do
    expect(Akami::WSSE::WSU_NAMESPACE).to eq(
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    )
  end

  it "contains the namespace for the PasswordText type" do
    expect(Akami::WSSE::PASSWORD_TEXT_URI).to eq(
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
    )
  end

  it "contains the namespace for the PasswordDigest type" do
    expect(Akami::WSSE::PASSWORD_DIGEST_URI).to eq(
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
    )
  end

  it "contains the namespace for Base64 Encoding type" do 
    expect(Akami::WSSE::BASE64_URI).to eq( 
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    )
  end

  describe "#credentials" do
    it "sets the username" do
      wsse.credentials "username", "password"
      expect(wsse.username).to eq("username")
    end

    it "sets the password" do
      wsse.credentials "username", "password"
      expect(wsse.password).to eq("password")
    end

    it "defaults to set digest to false" do
      wsse.credentials "username", "password"
      expect(wsse).not_to be_digest
    end

    it "sets digest to true if specified" do
      wsse.credentials "username", "password", :digest
      expect(wsse).to be_digest
    end
  end

  describe "#username" do
    it "sets the username" do
      wsse.username = "username"
      expect(wsse.username).to eq("username")
    end
  end

  describe "#password" do
    it "sets the password" do
      wsse.password = "password"
      expect(wsse.password).to eq("password")
    end
  end

  describe "#digest" do
    it "defaults to false" do
      expect(wsse).not_to be_digest
    end

    it "specifies whether to use digest auth" do
      wsse.digest = true
      expect(wsse).to be_digest
    end
  end

  describe "#to_xml" do
    context "with no credentials" do
      it "returns an empty String" do
        expect(wsse.to_xml).to eq("")
      end
    end

    context "with only a username" do
      before { wsse.username = "username" }

      it "returns an empty String" do
        expect(wsse.to_xml).to eq("")
      end
    end

    context "with only a password" do
      before { wsse.password = "password" }

      it "returns an empty String" do
        expect(wsse.to_xml).to eq("")
      end
    end

    context "with credentials" do
      before { wsse.credentials "username", "password" }

      it 'contains a wsse:Security tag' do
        expect(wsse.to_xml).to include("<wsse:Security xmlns:wsse=\"#{Akami::WSSE::WSE_NAMESPACE}\">")
      end

      it "contains a wsu:Id attribute" do
        expect(wsse.to_xml).to include('<wsse:UsernameToken wsu:Id="UsernameToken-1"')
      end

      it "increments the wsu:Id attribute count" do
        expect(wsse.to_xml).to include('<wsse:UsernameToken wsu:Id="UsernameToken-1"')
        expect(wsse.to_xml).to include('<wsse:UsernameToken wsu:Id="UsernameToken-2"')
      end

      it "contains the WSE and WSU namespaces" do
        expect(wsse.to_xml).to include(Akami::WSSE::WSE_NAMESPACE, Akami::WSSE::WSU_NAMESPACE)
      end

      it "contains the username and password" do
        expect(wsse.to_xml).to include("username", "password")
      end

      it "does not contain a wsse:Nonce tag" do
        expect(wsse.to_xml).not_to match(/<wsse:Nonce.*>.*<\/wsse:Nonce>/)
      end

      it "does not contain a wsu:Created tag" do
        expect(wsse.to_xml).not_to match(/<wsu:Created>.*<\/wsu:Created>/)
      end

      it "contains the PasswordText type attribute" do
        expect(wsse.to_xml).to include(Akami::WSSE::PASSWORD_TEXT_URI)
      end
    end

    context "with credentials and digest auth" do
      before { wsse.credentials "username", "password", :digest }

      it "contains the WSE and WSU namespaces" do
        expect(wsse.to_xml).to include(Akami::WSSE::WSE_NAMESPACE, Akami::WSSE::WSU_NAMESPACE)
      end

      it "contains the username" do
        expect(wsse.to_xml).to include("username")
      end

      it "does not contain the (original) password" do
        expect(wsse.to_xml).not_to include("password")
      end

      it "contains the Nonce base64 type attribute" do
        expect(wsse.to_xml).to include(Akami::WSSE::BASE64_URI)
      end

      it "contains a wsu:Created tag" do
        created_at = Time.now
        Timecop.freeze created_at do
          expect(wsse.to_xml).to include("<wsu:Created>#{created_at.utc.xmlschema}</wsu:Created>")
        end
      end

      it "contains the PasswordDigest type attribute" do
        expect(wsse.to_xml).to include(Akami::WSSE::PASSWORD_DIGEST_URI)
      end

      it "should reset the nonce every time" do
        created_at = Time.now
        Timecop.freeze created_at do
          nonce_regexp = /<wsse:Nonce.*>([^<]+)<\/wsse:Nonce>/
          nonce_first = Base64.decode64(nonce_regexp.match(wsse.to_xml)[1])
          nonce_second = Base64.decode64(nonce_regexp.match(wsse.to_xml)[1])
          expect(nonce_first).not_to eq(nonce_second)
        end
      end

      it "contains a properly hashed password" do
        xml_header = Nokogiri::XML(wsse.to_xml)
        xml_header.remove_namespaces!
        nonce = Base64.decode64(xml_header.xpath('//Nonce').first.content)
        created_at = xml_header.xpath('//Created').first.content
        password_hash = Base64.decode64(xml_header.xpath('//Password').first.content)
        expect(password_hash).to eq(Digest::SHA1.digest((nonce + created_at + "password")))
      end
    end

    context "with a signature" do
      let(:valid_signature) { fixture('akami/wsse/verify_signature/valid.xml') }
      let(:cert_path) { File.join(Bundler.root, 'spec', 'fixtures', 'akami', 'wsse', 'signature', 'cert.pem' ) }
      let(:password) { 'password' }

      let(:signature) {
        Akami::WSSE::Signature.new(
          Akami::WSSE::Certs.new(
            cert_file:            cert_path,
            private_key_file:     cert_path,
            private_key_password: password
          )
        )
      }

      before do
        wsse.signature = signature
        wsse.signature.document = valid_signature
      end

      it 'contains a wsse:BinarySecurityToken' do
        expect(wsse.to_xml).to include('<wsse:BinarySecurityToken')
      end

      it 'contains a wsse:Security tag' do
        expect(wsse.to_xml).to include("<wsse:Security xmlns:wsse=\"#{Akami::WSSE::WSE_NAMESPACE}\">")
      end

      it 'contains a wsse:BinarySecurityToken' do
        binary_security_token = 'MIIDIjCCAougAwIBAgIJAI53JnRgJIJwMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ4wDAYDVQQKEwVTYXZvbjEOMAwGA1UECxMFU2F2b24xDjAMBgNVBAMTBVNhdm9uMB4XDTE0MTIwMjAwMTMwMloXDTI0MTEyOTAwMTMwMlowajELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xDjAMBgNVBAoTBVNhdm9uMQ4wDAYDVQQLEwVTYXZvbjEOMAwGA1UEAxMFU2F2b24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM56hKF3+4SSUu8msb5HWMvp322yQL+luJ+Lt/r/ib7EPeb4UU68b+Wf3xIa3N1+w8tDQghCR4YuEIILKH/UGC785OldVJfikD4kxiwF4jB0RgdRK/JEG/UthHKqJID+oyijW4ws4MgZ/bWMhSbSVRioqcwe2JElg/m2TemKJkXDAgMBAAGjgc8wgcwwHQYDVR0OBBYEFKSd+UicrRDQS2NeLSEAZpipjk8EMIGcBgNVHSMEgZQwgZGAFKSd+UicrRDQS2NeLSEAZpipjk8EoW6kbDBqMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEOMAwGA1UEChMFU2F2b24xDjAMBgNVBAsTBVNhdm9uMQ4wDAYDVQQDEwVTYXZvboIJAI53JnRgJIJwMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAWI27+cDx3U53zaJROXKfQutqUZzZz9B0NzQ0vlN2h5UbACGbXH9C1wLzMBvNjgEiK+/jHSadSDgfvADv+2hCsFw8eNgbisWiV5yvDyTqttg3cSJHz8jRDeA+jnvaC9Y//AoRr/WGKKU3FY40J7pQKcQNczGUzCS+ag0IO64agTs='
        expect(wsse.to_xml).to include(binary_security_token)
      end

      it 'contains a Signature tag' do
        namespace = 'http://www.w3.org/2000/09/xmldsig#'
        expect(wsse.to_xml).to include("<Signature xmlns=\"#{namespace}\"")
      end

      it 'contains a CanonicalizationMethod tag' do
        namespace = 'http://www.w3.org/2001/10/xml-exc-c14n#'
        expect(wsse.to_xml).to include("<CanonicalizationMethod Algorithm=\"#{namespace}\"")
      end

      it 'contains a SignatureMethod tag' do
        namespace = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        expect(wsse.to_xml).to include("<SignatureMethod Algorithm=\"#{namespace}\"")
      end

      it 'contains a DigestValue tag' do
        digest_value = 'YrKqrE99N7hNGYEvrhifL/LaxKQ='
        expect(wsse.to_xml).to include("<DigestValue>#{digest_value}</DigestValue>")
      end

      it 'contains a SignatureValue tag' do
        signature_value = 'MF8Mn/SgQjQICfyfZpYHToubaDAvJG76kiicDYrbXXHdF/Hvwz7+/IfRexlodhBrbuPIWqfbRnfgb65UM4a5hbOu9WbLnz8kuEujcUo3xKczEvkl+kjMOYty7GYaXWTj+6IkNMl9FJ+PGf8QNzD52MwhMOLq5t94WHSB0jDDiIo='
        expect(wsse.to_xml).to include("<SignatureValue>#{signature_value}</SignatureValue>")
      end

      it 'contains a wsse:SecurityTokenReference tag' do
        expect(wsse.to_xml).to include("<wsse:SecurityTokenReference xmlns:wsu=\"#{Akami::WSSE::WSU_NAMESPACE}\"")
      end

      it 'contains a wsse:Reference tag' do
        namespace = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
        expect(wsse.to_xml).to include("<wsse:Reference ValueType=\"#{namespace}\"")
      end

      describe 'with credentials' do
        before { wsse.credentials "username", "password" }

        it "contains the username and password" do
          expect(wsse.to_xml).to include("username", "password")
        end

        it "contains the PasswordText type attribute" do
          expect(wsse.to_xml).to include(Akami::WSSE::PASSWORD_TEXT_URI)
        end
      end

      describe 'with a timestamp' do
        before { wsse.timestamp = true }

        it "contains a wsse:Timestamp node" do
          expect(wsse.to_xml).to include('<wsu:Timestamp wsu:Id="Timestamp-1" ' +
            "xmlns:wsu=\"#{Akami::WSSE::WSU_NAMESPACE}\">")
        end
  
        it "contains a wsu:Created node defaulting to Time.now" do
          created_at = Time.now
          Timecop.freeze created_at do
            expect(wsse.to_xml).to include("<wsu:Created>#{created_at.utc.xmlschema}</wsu:Created>")
          end
        end
  
        it "contains a wsu:Expires node defaulting to Time.now + 60 seconds" do
          created_at = Time.now
          Timecop.freeze created_at do
            expect(wsse.to_xml).to include("<wsu:Expires>#{(created_at + 60).utc.xmlschema}</wsu:Expires>")
          end
        end
      end

      describe 'with a timestamp and credentials' do
        before do
          wsse.credentials "username", "password"
          wsse.timestamp = true
        end

        it "contains the username and password" do
          expect(wsse.to_xml).to include("username", "password")
        end

        it "contains a wsse:Timestamp node" do
          expect(wsse.to_xml).to include('<wsu:Timestamp wsu:Id="Timestamp-2" ' +
            "xmlns:wsu=\"#{Akami::WSSE::WSU_NAMESPACE}\">")
        end
      end
    end

    context "with #timestamp set to true" do
      before { wsse.timestamp = true }

      it "contains a wsse:Timestamp node" do
        expect(wsse.to_xml).to include('<wsu:Timestamp wsu:Id="Timestamp-1" ' +
          "xmlns:wsu=\"#{Akami::WSSE::WSU_NAMESPACE}\">")
      end

      it "contains a wsu:Created node defaulting to Time.now" do
        created_at = Time.now
        Timecop.freeze created_at do
          expect(wsse.to_xml).to include("<wsu:Created>#{created_at.utc.xmlschema}</wsu:Created>")
        end
      end

      it "contains a wsu:Expires node defaulting to Time.now + 60 seconds" do
        created_at = Time.now
        Timecop.freeze created_at do
          expect(wsse.to_xml).to include("<wsu:Expires>#{(created_at + 60).utc.xmlschema}</wsu:Expires>")
        end
      end
    end

    context "with #created_at" do
      before { wsse.created_at = Time.now + 86400 }

      it "contains a wsu:Created node with the given time" do
        expect(wsse.to_xml).to include("<wsu:Created>#{wsse.created_at.utc.xmlschema}</wsu:Created>")
      end

      it "contains a wsu:Expires node set to #created_at + 60 seconds" do
        expect(wsse.to_xml).to include("<wsu:Expires>#{(wsse.created_at + 60).utc.xmlschema}</wsu:Expires>")
      end
    end

    context "with #expires_at" do
      before { wsse.expires_at = Time.now + 86400 }

      it "contains a wsu:Created node defaulting to Time.now" do
        created_at = Time.now
        Timecop.freeze created_at do
          expect(wsse.to_xml).to include("<wsu:Created>#{created_at.utc.xmlschema}</wsu:Created>")
        end
      end

      it "contains a wsu:Expires node set to the given time" do
        expect(wsse.to_xml).to include("<wsu:Expires>#{wsse.expires_at.utc.xmlschema}</wsu:Expires>")
      end
    end

    context "with credentials and timestamp" do
      before do
        wsse.credentials "username", "password"
        wsse.timestamp = true
      end

      it "contains a wsu:Created node" do
        expect(wsse.to_xml).to include("<wsu:Created>")
      end

      it "contains a wsu:Expires node" do
        expect(wsse.to_xml).to include("<wsu:Expires>")
      end

      it "contains the username and password" do
        expect(wsse.to_xml).to include("username", "password")
      end
    end
  end

end
