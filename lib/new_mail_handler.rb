module NewMailHandler
  def self.included(receiver)
    receiver.class_eval do
      def add_attachments(obj)
        if email.attachments && email.attachments.any?
          email.attachments.each do |attachment|
            obj.attachments << Attachment.create(:container => obj,
                                                 :file => attachment.decoded,
                                                 :filename => attachment.filename,
                                                 :author => user,
                                                 :content_type => attachment.mime_type)
          end 
        end 
        if email.html_part
          obj.attachments << Attachment.create(:container => obj,
                                               :file => email.html_part.body.decoded,
                                               :filename => 'EMAIL-BODY'+Date.today.strftime("%Y-%m-%d")+'.html',
                                               :author => user,
                                               :content_type => 'text/html')
        end 
      end

      def plain_text_body
        return @plain_text_body unless @plain_text_body.nil?
        part = email.text_part || email.html_part || email
        case part.charset
          when 'ks_c_5601-1987'
            pcharset = 'CP949'
          else
            pcharset = part.charset
        end 
        @plain_text_body = Redmine::CodesetUtil.to_utf8(part.body.decoded, pcharset)

        # strip html tags and remove doctype directive
        unless email.text_part
          @plain_text_body = strip_tags(@plain_text_body.strip)
        end 
        @plain_text_body.sub! %r{^<!DOCTYPE .*$}, ''
        @plain_text_body
      end 
    end
  end
end
