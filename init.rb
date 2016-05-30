Redmine::Plugin.register :redmine_travelsystem do
  name 'Redmine Travelsystem plugin'
  author 'lek'
  description 'Patches for Redmine'
  version '0.0.5'
  url 'http://travelsystem.ru'
  author_url 'http://travelsystem.ru'
  requires_redmine :version_or_higher => '2.4.0'
  settings :default => {
    'ts_settings_actionmailer_log' => false,
    'ts_settings_mailer_log' => false,
    'ts_settings_l4_log' => false,
    'ts_settings_issue_open_by_email' => false,
    'ts_settings_add_resent_from' => false,
    'ts_settings_add_anonymous_from' => false,
    'ts_settings_message_id_re' => false,
    'ts_settings_changeauthor' => false,
    'ts_settings_verify_ssl_disable' => false },
    :partial => 'settings/ts_settings'

  project_module :issue_tracking do
    permission :change_author, :require => :member
  end 

  Rails.configuration.to_prepare do
    if Setting['plugin_redmine_travelsystem']['ts_settings_verify_ssl_disable']
      OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
    end


    #Логгирование писем ActionMailer::Base.logger
    if Setting['plugin_redmine_travelsystem']['ts_settings_actionmailer_log']
      require 'actionmailer_logger'
    end

	#Логгирование событий класса Mailer (app/models/mailer.rb)
    if Setting['plugin_redmine_travelsystem']['ts_settings_mailer_log']
      require 'mailer_logger'
    end
    #Добавлена функция отправки MailHandler при ошибке приёма письма
    #Исправлена функция news_added - рассылка новости для всех пользователей, даже тех, кто не подписан получать что-либо
    require 'mailer_patch'
    Mailer.send :include, MailerPatch
    #require 'activerecord_logger'

    #Логгирование уровня SMTP
    if Setting['plugin_redmine_travelsystem']['ts_settings_l4_log']
      require 'mail_logger'
      require 'mail_patch_logger'
      #Mail::SMTP.send :include, MailPatchLogger
    end

    require 'projects_helper_patch'
    ProjectsHelper.send :include, ProjectsHelperPatch


    #Патчи для приёма письма через почту
    require 'mail_handler_patch'
    MailHandler.send :include, MailHandlerPatch 


    require 'issue_statuses_controller_patch'
    IssueStatusesController.send :include, IssueStatusesControllerPatch


    #Патч mail gem 2.5.4 https://github.com/mikel/mail 2.5.4
	#Устраняет проблему с обрезанным заголовком Subject
    if Mail::VERSION.version == "2.5.4"
      require "mail_patch_word_encode"
      Mail::UnstructuredField.send :include, MailPatchWordEncode
	  #require 'mail_patch_subject_decode'
	  #Mail::Encodings.send :include, MailPatchSubjectDecode
    end

	require 'custom_logger'
	require 'patches'
  end
end
