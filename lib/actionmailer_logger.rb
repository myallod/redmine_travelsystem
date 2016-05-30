require 'action_mailer'
require 'active_support'

logfile = File.open("#{Rails.root}/log/actionmailer.log", 'a')
logfile.sync = true
ActionMailer::Base.raise_delivery_errors = true
ActionMailer::Base.logger = ActiveSupport::BufferedLogger.new(logfile)
