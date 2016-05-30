class CustomLogger < Logger; end

logfile = File.open("#{Rails.root}/log/custom.log", 'a')
logfile.sync = true
CUSTOM_LOGGER = CustomLogger.new(logfile)
