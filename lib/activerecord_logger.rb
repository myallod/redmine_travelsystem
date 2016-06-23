require 'active_support'

logfile = File.open("#{Rails.root}/log/activerecord.log", 'a')
logfile.sync = true
ActiveRecord::Base.logger = ActiveSupport::Logger.new(logfile)
#ActiveRecord::Base.logger.level = debug
