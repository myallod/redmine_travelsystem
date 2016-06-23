require 'active_support'

logfile = File.open("#{Rails.root}/log/smtp.log", 'a')
logfile.sync = true
MAILLOGGER = ActiveSupport::Logger.new(logfile)
#SMTPLOGGER.level = debug
