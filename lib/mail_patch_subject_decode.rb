# encoding: utf-8

module MailPatchSubjectDecode
  def self.included(base)
    base.send(:include, InstanceMethods)
	base.class_eval do
      unloadable
      alias_method_chain :Encodings.collapse_adjacent_encodings, :Encodings.ts_collapse_adjacent_encodings
    end
  end

  module InstanceMethods
    include Mail::Patterns
    extend Mail::Utilities

    private
      def collapse_adjacent_encodings(str)
        lines = str.split(/(\?=)\s*(=\?)/).each_slice(2).map(&:join)
        results = []
        previous_encoding = nil 

        lines.each do |line|
        encoding = split_value_encoding_from_string(line)

        if encoding == previous_encoding
          line = results.pop + line
          #line.gsub!(/\?\=\=\?.+?\?[QqBb]\?/m, '')
        end

        previous_encoding = encoding
        results << line
      end

      results
    end
  end
end
