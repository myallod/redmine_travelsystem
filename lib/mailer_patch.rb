module MailerPatch

  def self.included(base)
    base.send(:include, InstanceMethods)

    base.class_eval do
      unloadable
      alias_method_chain :news_added, :tsnewsadded
      alias_method_chain :mylogger, :tsmylogger
      alias_method_chain :issue_add, :tsissueadd
      alias_method_chain :issue_edit, :tsissueedit
    end
  end

  module InstanceMethods

    def failed_receive(from, to, error, email)
      recipients = User.active.where(:admin => true).all.collect { |u| u.mail }.compact
	  @efrom = from
	  @eto = to
	  @eerror = error
	  attachments['email.msg'] = email.to_s
      mail :to => recipients, :subject => "#{Setting.app_title} MailHandler - #{from}"
    end

    def news_added_with_tsnewsadded(news)
      redmine_headers 'Project' => news.project.identifier
      @author = news.author
      message_id news
      references news
      @news = news
      @news_url = url_for(:controller => 'news', :action => 'show', :id => news)
      mail :to => news.project.members.collect {|m| m.user}.collect {|u| u.mail},
        :subject => "[#{news.project.name}] #{l(:label_news)}: #{news.title}"
    end

    #Builds a mail for notifying to_users and cc_users about a new issue
    def issue_add_with_tsissueadd(issue, to_users, cc_users)
      redmine_headers 'Project' => issue.project.identifier,
                      'Issue-Id' => issue.id,
                      'Issue-Author' => issue.author.login
      redmine_headers 'Issue-Assignee' => issue.assigned_to.login if issue.assigned_to
      message_id issue
      references issue
      @author = issue.author
      @issue = issue
      @users = to_users + cc_users
      @issue_url = url_for(:controller => 'issues', :action => 'show', :id => issue)
      mail :to => to_users,
        :cc => cc_users,
        :subject => "[#{issue.project.name} - #{issue.tracker.name} ##{issue.id}] #{issue.subject}"
    end
	

    def issue_edit_with_tsissueedit(journal, to_users, cc_users)
      issue = journal.journalized
      redmine_headers 'Project' => issue.project.identifier,
                      'Issue-Id' => issue.id,
                      'Issue-Author' => issue.author.login
      redmine_headers 'Issue-Assignee' => issue.assigned_to.login if issue.assigned_to
      message_id journal
      references issue
      @author = journal.user
      s = "[#{issue.project.name} - #{issue.tracker.name} ##{issue.id}] #{issue.subject}"
      @issue = issue
      @users = to_users + cc_users
      @journal = journal
      @journal_details = journal.visible_details(@users.first)
      @issue_url = url_for(:controller => 'issues', :action => 'show', :id => issue, :anchor => "change-#{journal.id}")
      if mylogger
        mylogger.info "Mailer (pid: #{Process.pid}): issue_edit_with_tsissueedit; to:#{to_users.map(&:mail)}, cc:#{cc_users.map(&:mail)}, subject: #{s} at #{__FILE__}:#{__LINE__}"
      end
      mail :to => to_users,
       :cc => cc_users,
       :subject => s
     end

    private
      def mylogger_with_tsmylogger
        if Setting['plugin_redmine_travelsystem']['ts_settings_actionmailer_log']
          MAILERLOGGER
        else
          Rails.logger
        end
      end
  end
end

