require 'mail/fields/common/common_field'
# encoding: utf-8

module MailPatchWordEncode
  def self.included(base)
    base.send(:include, InstanceMethods)
	base.class_eval do
      unloadable
      alias_method_chain :fold, :tsfold
    end
  end

  module InstanceMethods
    include Mail::CommonField
    include Mail::Utilities

    attr_accessor :charset
    attr_reader :errors

    private
    def fold_with_tsfold(prepend = 0) # :nodoc:
      encoding       = normalized_encoding
      decoded_string = decoded.to_s
      should_encode  = decoded_string.not_ascii_only?
      if should_encode
        first = true
        words = decoded_string.split(/[ \t]/).map do |word|
          if first
            first = !first
          else
            word = " " << word
          end
          if word.not_ascii_only?
            word
          else
            word.scan(/.{7}|.+$/)
          end
        end.flatten
      else
        words = decoded_string.split(/[ \t]/)
      end

      folded_lines   = []
      while !words.empty?
        limit = 78 - prepend
        limit = limit - 7 - encoding.length if should_encode
        line = ""
        while !words.empty?
          break unless word = words.first.dup
          if charset && word.respond_to?(:encode!)
            begin
              word.encode!(charset)
            rescue Encoding::UndefinedConversionError
              word.force_encoding charset
            end
          end
          #word.encode!(charset) if charset && word.respond_to?(:encode!)
          word = encode(word) if should_encode
          word = encode_crlf(word)
          # Skip to next line if we're going to go past the limit
          # Unless this is the first word, in which case we're going to add it anyway
          # Note: This means that a word that's longer than 998 characters is going to break the spec. Please fix if this is a problem for you.
          # (The fix, it seems, would be to use encoded-word encoding on it, because that way you can break it across multiple lines and
          # the linebreak will be ignored)
          break if !line.empty? && (line.length + word.length + 1 > limit)
          # Remove the word from the queue ...
          words.shift
          # Add word separator
          line << " " unless (line.empty? || should_encode)
          # ... add it in encoded form to the current line
          line << word
        end
        # Encode the line if necessary
        line = "=?#{encoding}?Q?#{line}?=" if should_encode
        # Add the line to the output and reset the prepend
        folded_lines << line
        prepend = 0
      end
      folded_lines
    end
  end
end
