module MailerPatch

  def self.included(base)
    base.send(:include, InstanceMethods)

    base.class_eval do
      unloadable
      alias_method_chain :news_added, :tsnewsadded
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
      @news = news
      @news_url = url_for(:controller => 'news', :action => 'show', :id => news)
      mail :to => news.project.members.collect {|m| m.user}.collect {|u| u.mail},
        :subject => "[#{news.project.name}] #{l(:label_news)}: #{news.title}"
    end
  end
end

