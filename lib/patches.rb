# patch config/initializer/10-patches.rb
# Changes how sent emails are logged
# # Rails doesn't log cc and bcc which is misleading when using bcc only (#12090)
module ActionMailer
  class LogSubscriber < ActiveSupport::LogSubscriber
    def deliver(event)
      recipients = [:to, :cc, :bcc].inject("") do |s, header|
        r = Array.wrap(event.payload[header])
        if r.any?
          s << "\n  #{header}: #{r.join(', ')}"
        end
        s
      end
      info("\nSent email \"#{event.payload[:subject]}\" #{recipients}\n  #{DateTime.now.to_s}")
      debug(event.payload[:mail])
    end

	def receive(event)
      info("\nReceived email \"#{event.payload[:subject]}\"\n from: #{event.payload[:from]}\n #{DateTime.now.to_s} (%.1fms)" % event.duration)
      debug(event.payload[:mail])
    end
  end
end
