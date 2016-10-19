namespace :redmine do
  namespace :redmine_travelsystem do
    desc "Dump redmine database and put dump to db/backups/"
    task :dump_db => :environment do
      #puts "dumpdb task"
      cmd = nil
      targetdir = "#{Rails.root}/db/backups/"
      Dir.mkdir(targetdir) unless File.exists?(targetdir)
      file = "#{Rails.root}/.redmine.cnf"
      with_config do |app, host, db, username, password|
        begin
	  fd = File.open(file, 'w')
	  fd.write("[client]\nuser=#{username}\npassword=#{password}\nhost=#{host}")
	rescue IOError => e
	  puts "Error #{e}"
	ensure
	  fd.close unless fd.nil?
	end
        cmd = "/usr/bin/mysqldump --defaults-file=#{Rails.root}/.redmine.cnf --opt #{db} > #{Rails.root}/db/backups/#{db}.sql"
      end
      unless cmd.nil?
        #puts cmd
        system(cmd)
	File.delete(file) if File.exists?(file)
      end
    end

    private
      def with_config
        yield Rails.application.class.parent_name.underscore,
        ActiveRecord::Base.connection_config[:host],
        ActiveRecord::Base.connection_config[:database],
        ActiveRecord::Base.connection_config[:username],
        ActiveRecord::Base.connection_config[:password]
      end
  end
end

