Redmine::Plugin.register :redmine_travelsystem do
  name 'Redmine Travelsystem plugin'
  author 'lek'
  description 'Patches for Redmine'
  version '0.0.2'
  url 'http://travelsystem.ru'
  author_url 'http://travelsystem.ru'
  requires_redmine :version_or_higher => '2.2.0'

  Rails.configuration.to_prepare do
    require 'projects_helper_patch'
    ProjectsHelper.send :include, ProjectsHelperPatch
    require 'news_to_all_members'
    Mailer.send :include, NewsSendNotificationToAllMembers
	require 'new_mail_handler'
	MailHandler.send :include, NewMailHandler
	#require 'custom_logger'
	require 'patches'
  end
end
