require 'active_support'

logfile = File.open("#{Rails.root}/log/mailer.log", 'a')
logfile.sync = true
MAILERLOGGER = ActiveSupport::Logger.new(logfile)
