module Akami
  class WSSE
    # Contains certs for WSSE::Signature
    class Certs

      def initialize(certs = {})
        certs.each do |key, value|
          self.send :"#{key}=", value
        end
      end

      attr_accessor :cert_file, :private_key_file, :private_key_password

      # Returns an <tt>OpenSSL::X509::Certificate</tt> for the +cert_file+.
      def cert
        @cert ||= case File.extname(cert_file)
        when ".p12"
          OpenSSL::PKCS12.new(File.read(cert_file), private_key_password).certificate
        else
          OpenSSL::X509::Certificate.new File.read(cert_file)
        end if cert_file
      end

      # Returns an <tt>OpenSSL::PKey::RSA</tt> for the +private_key_file+.
      def private_key
        @private_key ||= case File.extname(private_key_file)
        when ".p12"
          OpenSSL::PKCS12.new(File.read(private_key_file), private_key_password).key
        else
          OpenSSL::PKey::RSA.new(File.read(private_key_file), private_key_password)
        end if private_key_file
      end

    end
  end
end
