require 'nokogiri'

module Akami
  class WSSE
    class InvalidSignature < RuntimeError; end

    # Validating WSSE signed messages.
    class VerifySignature
      include Akami::C14nHelper

      class InvalidDigest < RuntimeError; end
      class InvalidSignedValue < RuntimeError; end

      attr_reader :document

      def initialize(xml)
        @document = Nokogiri::XML(xml.to_s, &:noblanks)
      end

      # Returns XML namespaces that are used internally for document querying.
      def namespaces
        @namespaces ||= {
          wse: Akami::WSSE::WSE_NAMESPACE,
          ds:  'http://www.w3.org/2000/09/xmldsig#',
          wsu: Akami::WSSE::WSU_NAMESPACE,
        }
      end

      # Allows to replace used XML namespaces if anyone will ever need. +hash+ should be a +Hash+ with symbol keys +:wse+, +:ds+, and +:wsu+.
      attr_writer :namespaces

      # Returns signer's certificate, bundled in signed document
      def certificate
        certificate_value = document.at_xpath('//wse:Security/wse:BinarySecurityToken', namespaces).text.strip
        OpenSSL::X509::Certificate.new Base64.decode64(certificate_value)
      end

      # Validates document signature, returns +true+ on success, +false+ otherwise.
      def valid?
        verify
      rescue InvalidDigest, InvalidSignedValue
        return false
      end

      # Validates document signature and digests and raises if anything mismatches.
      def verify!
        verify
      rescue InvalidDigest, InvalidSignedValue => e
        raise InvalidSignature, e.message
      end

      private

      def verify
        document.xpath('//wse:Security/ds:Signature/ds:SignedInfo/ds:Reference', namespaces).each do |ref|
          element_id = ref.attributes['URI'].value[1..-1] # strip leading '#'
          element = document.at_xpath(%(//*[@wsu:Id="#{element_id}"]), namespaces)
          raise InvalidDigest, "Invalid Digest for #{element_id}" unless supplied_digest(element) == generate_digest(element)
        end

        data = canonicalize(signed_info)
        signature = Base64.decode64(signature_value)

        certificate.public_key.verify(OpenSSL::Digest::SHA1.new, signature, data) or raise InvalidSignedValue, "Could not verify the signature value"
      end

      def signed_info
        document.at_xpath('//wse:Security/ds:Signature/ds:SignedInfo', namespaces)
      end

      def generate_digest(element)
        element = document.at_xpath(element, namespaces) if element.is_a? String
        xml = canonicalize(element)
        digest(xml).strip
      end

      def supplied_digest(element)
        element = document.at_xpath(element, namespaces) if element.is_a? String
        find_digest_value element.attributes['Id'].value
      end

      def signature_value
        element = document.at_xpath('//wse:Security/ds:Signature/ds:SignatureValue', namespaces)
        element ? element.text : ""
      end

      def find_digest_value(id)
        document.at_xpath(%(//wse:Security/ds:Signature/ds:SignedInfo/ds:Reference[@URI="##{id}"]/ds:DigestValue), namespaces).text
      end

      def digest(string)
        Base64.encode64 OpenSSL::Digest::SHA1.digest(string)
      end
    end
  end
end
