module Akami
  module HashHelper
    # Returns a new Hash with +hash+ and +other_hash+ merged recursively.
    # Modifies +hash+ in place.
    def self.deep_merge!(hash, other_hash)
      other_hash.each_pair do |k,v|
        tv = hash[k]
        hash[k] = tv.is_a?(Hash) && v.is_a?(Hash) ? deep_merge!(tv.dup, v) : v
      end
      hash
    end
  end
end
