# encoding: utf-8
require_dependency 'mail/check_delivery_params'


module MailPatchLogger
  def self.included(base)
    base.send(:include, InstanceMethods)
	base.class_eval do
      unloadable
      alias_method_chain :deliver!, :tsdeliver!
    end
  end

  module InstanceMethods
    def deliver_with_tsdeliver!(mail)
      smtp_from, smtp_to, message = check_delivery_params(mail)

      smtp = Net::SMTP.new(settings[:address], settings[:port])
      STDERR.puts "DBG NET::SMTP at file #{__FILE__}:#{__LINE__}"
      smtp.set_debug_output $stderr
      if settings[:tls] || settings[:ssl]
        if smtp.respond_to?(:enable_tls)
          smtp.enable_tls(ssl_context)
        end
      elsif settings[:enable_starttls_auto]
        if smtp.respond_to?(:enable_starttls_auto)
          smtp.enable_starttls_auto(ssl_context)
        end
      end

      response = nil 
      smtp.start(settings[:domain], settings[:user_name], settings[:password], settings[:authentication]) do |smtp_obj|
        response = smtp_obj.sendmail(message, smtp_from, smtp_to)
      end 

      if settings[:return_response]
        response
      else
        self
      end 
    end 
  end
end
