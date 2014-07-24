Redmine::Plugin.register :redmine_travelsystem do
  name 'Redmine Travelsystem plugin'
  author 'lek'
  description 'Patches for Redmine'
  version '0.0.3'
  url 'http://travelsystem.ru'
  author_url 'http://travelsystem.ru'
  requires_redmine :version_or_higher => '2.3.0'

  Rails.configuration.to_prepare do
    require 'projects_helper_patch'
    ProjectsHelper.send :include, ProjectsHelperPatch
    require 'mailer_patch'
    Mailer.send :include, MailerPatch
	require 'mail_handler_patch'
	MailHandler.send :include, MailHandlerPatch 
	require 'issue_statuses_controller_patch'
    IssueStatusesController.send :include, IssueStatusesControllerPatch
    #patch https://github.com/mikel/mail 2.5.4
    if Mail::VERSION.version == "2.5.4"
      require "mail_patch"
      Mail::UnstructuredField.send :include, MailPatch
    end
	#require 'custom_logger'
	require 'patches'
	require 'warning_message_hook'
  end
end
