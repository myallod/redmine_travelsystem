module NewsSendNotificationToAllMembers
  def self.included(receiver)
    receiver.class_eval do
      def news_added(news)
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
end

