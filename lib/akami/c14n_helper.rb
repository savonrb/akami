module Akami
  module C14nHelper
    def canonicalize(xml, inclusive_namespaces = nil)
      return unless xml
      xml.canonicalize Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive_namespaces
    end
  end
end
