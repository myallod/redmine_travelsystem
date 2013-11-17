require_dependency 'mail_handler'

module MailHandlerPatch
  def self.included(base)
	#base.extend(ClassMethods)
    base.send(:include, InstanceMethods)
	base.class_eval do
      unloadable
      alias_method_chain :logger, :tslogger
      alias_method_chain :receive, :tsreceive
      alias_method_chain :dispatch, :tsdispatch
      alias_method_chain :receive_issue, :tsreceiveissue
      alias_method_chain :receive_issue_reply, :tsreceiveissuereply
      alias_method_chain :receive_journal_reply, :tsreceivejournalreply
      alias_method_chain :receive_message_reply, :tsreceivemessagereply
      alias_method_chain :add_attachments, :tsaddattachments
      alias_method_chain :plain_text_body, :tsplaintextbody
      alias_method_chain :cleanup_body, :tscleanupbody
      alias_method_chain :create_user_from_email, :tscreateuserfromemail
      alias_method_chain :add_user_to_group, :tsaddusertogroup
    end
  end

#  module ClassMethods
#    def receive(email, options={})
#      @@handler_options = options.dup
#      @@handler_options[:issue] ||= {}
#
#      if @@handler_options[:allow_override].is_a?(String)
#        @@handler_options[:allow_override] = @@handler_options[:allow_override].split(',').collect(&:strip)
#      end
#      @@handler_options[:allow_override] ||= []
#      @@handler_options[:allow_override] << 'project' unless @@handler_options[:issue].has_key?(:project)
#      @@handler_options[:allow_override] << 'status' unless @@handler_options[:issue].has_key?(:status)
# 
#      @@handler_options[:no_account_notice] = (@@handler_options[:no_account_notice].to_s == '1')
#      @@handler_options[:no_notification] = (@@handler_options[:no_notification].to_s == '1')
#      @@handler_options[:no_permission_check] = (@@handler_options[:no_permission_check].to_s == '1')
# 
#      email.force_encoding('ASCII-8BIT') if email.respond_to?(:force_encoding)
#      super(email)
#    end
#	cattr_accessor :handler_options
# end

  module InstanceMethods
    class UnauthorizedAction < StandardError; end
    class MissingInformation < StandardError; end

      def logger_with_tslogger
        ActionMailer::Base.logger ? ActionMailer::Base.logger : Rails.logger
      end

      def msg_failed_receive(sender, message, email)
        if logger; logger.info "MailHandler: msg_failed_receive at #{__FILE__}:#{__LINE__}"; end 
        m = Mailer
        s = m.async_smtp_settings
        m.delivery_method=:smtp
        m.smtp_settings = s
        m.failed_receive(sender, ARGV[ARGV.index { |b| b if b.include?('project=')}], message, email).deliver
      end

      def receive_with_tsreceive(email)
        if logger; logger.info "MailHandler: receive_with_tsreceive at #{__FILE__}:#{__LINE__}"; end 
        @ho = self.class.class_variable_get("@@handler_options")
        @email = email
        sender_email = email.from.to_a.first.to_s.strip
        # Ignore emails received from the application emission address to avoid hell cycles
        if sender_email.downcase == Setting.mail_from.to_s.strip.downcase
          msg = "MailHandler: ignoring email from Redmine emission address [#{sender_email}] at #{__FILE__}:#{__LINE__}"
          if logger; logger.info msg; end 
          msg_failed_receive(sender_email, msg, @email)
          return false
        end
        # Ignore auto generated emails
        self.class.ignored_emails_headers.each do |key, ignored_value|
          value = email.header[key]
          if value
            value = value.to_s.downcase
            if (ignored_value.is_a?(Regexp) && value.match(ignored_value)) || value == ignored_value
              msg = "MailHandler: ignoring email with #{key}:#{value} header at #{__FILE__}:#{__LINE__}"
              if logger; logger.info msg; end
              msg_failed_receive(sender_email, msg, @email)
              return false
            end
          end
        end
        @user = User.find_by_mail(sender_email) if sender_email.present?
        if @user && !@user.active?
          msg = "MailHandler: ignoring email from non-active user [#{@user.login}] at #{__FILE__}:#{__LINE__}"
          if logger; logger.info msg; end
          msg_failed_receive(sender_email, msg, @email)
          return false
        end
        if @user.nil?
          # Email was submitted by an unknown user
          case @ho[:unknown_user]
          when 'accept'
            @user = User.anonymous
          when 'create'
            @user = create_user_from_email
            if @user
              if logger; logger.info "MailHandler: [#{@user.login}] account created at #{__FILE__}:#{__LINE__}"; end
              add_user_to_group(@ho[:default_group])
              unless @ho[:no_account_notice]
                Mailer.account_information(@user, @user.password).deliver
              end
            else
              msg = "MailHandler: could not create account for [#{sender_email}] at #{__FILE__}:#{__LINE__}"
              if logger; logger.info msg; end
              msg_failed_receive(sender_email, msg, @email)
              return false
            end
          else
            # Default behaviour, emails from unknown users are ignored
            msg = "MailHandler: ignoring email from unknown user [#{sender_email}] at #{__FILE__}:#{__LINE__}"
            if logger; logger.info msg; end
            msg_failed_receive(sender_email, msg, @email)
            return false
          end
        end
        User.current = @user
        dispatch
      end

      private
      MESSAGE_ID_RE = %r{^<?redmine\.([a-z0-9_]+)\-(\d+)\.\d+@}
      ISSUE_REPLY_SUBJECT_RE = %r{\[[^\]]*#(\d+)\]}
      MESSAGE_REPLY_SUBJECT_RE = %r{\[[^\]]*msg(\d+)\]}

      def dispatch_with_tsdispatch
        if logger; logger.info "MailHandler: dispatch_with_tsdispatch at #{__FILE__}:#{__LINE__}"; end 
        headers = [email.in_reply_to, email.references].flatten.compact
        subject = email.subject.to_s
        if headers.detect {|h| h.to_s =~ MESSAGE_ID_RE}
          klass, object_id = $1, $2.to_i
          method_name = "receive_#{klass}_reply"
          if self.class.private_instance_methods.collect(&:to_s).include?(method_name)
            if logger; logger.info "MailHandler: dispatch: send method_name: #{method_name} object_id #{object_id} at #{__FILE__}:#{__LINE__}"; end
            send method_name, object_id
          else
            # ignoring it
          end
          if logger; logger.info "MailHandler: dispatch: MESSAGE_ID_RE at #{__FILE__}:#{__LINE__}"; end
        elsif m = subject.match(ISSUE_REPLY_SUBJECT_RE)
          if logger; logger.info "MailHandler: dispatch: ISSUE_REPLY_SUBJECT_RE at #{__FILE__}:#{__LINE__}"; end
          receive_issue_reply(m[1].to_i)
        elsif m = subject.match(MESSAGE_REPLY_SUBJECT_RE)
          if logger; logger.info "MailHandler: dispatch: MESSAGE_REPLY_SUBJECT_RE at #{__FILE__}:#{__LINE__}"; end
          receive_message_reply(m[1].to_i)
        else
          if logger; logger.info "MailHandler: dispatch_to_default at #{__FILE__}:#{__LINE__}"; end
          dispatch_to_default
        end
      rescue ActiveRecord::RecordInvalid => e
        # TODO: send a email to the user
        msg = "MailHandler: #{e.message} at #{__FILE__}:#{__LINE__}"
        if logger; logger.info msg; end
        msg_failed_receive(@user.email, msg, @email)
        false
      rescue MissingInformation => e
        msg = "MailHandler: missing information from #{user}: #{e.message} at #{__FILE__}:#{__LINE__}"
        if logger; logger.info msg; end
        msg_failed_receive(@user.email, msg, @email)
        false
      rescue UnauthorizedAction => e
        msg = "MailHandler: unauthorized attempt from #{user} at #{__FILE__}:#{__LINE__}"
        if logger; logger.info msg; end
        msg_failed_receive(@user.email, msg, @email)
        false
      end

      def receive_issue_with_tsreceiveissue
        if logger; logger.info "MailHandler: receive_issue_with_tsreceiveissue at #{__FILE__}:#{__LINE__}"; end 
        project = target_project
        # check permission
        unless @ho[:no_permission_check]
          raise UnauthorizedAction unless user.allowed_to?(:add_issues, project)
        end

        issue = Issue.new(:author => user, :project => project)
        issue.safe_attributes = issue_attributes_from_keywords(issue)
        issue.safe_attributes = {'custom_field_values' => custom_field_values_from_keywords(issue)}
        issue.subject = cleaned_up_subject
        if issue.subject.blank?
          issue.subject = '(no subject)'
        end
        issue.description = cleaned_up_text_body

        # add To and Cc as watchers before saving so the watchers can reply to Redmine
        add_watchers(issue)
        issue.save!
        add_attachments(issue)
        if logger; logger.info "MailHandler: issue ##{issue.id} created by #{user} (#{email.from.to_a.first.to_s.strip}) at #{__FILE__}:#{__LINE__}"; end
        issue
      end

      def receive_issue_reply_with_tsreceiveissuereply(issue_id, from_journal=nil)
        if logger; logger.info "MailHandler: receive_issue_reply_with_tsreceiveissuereply at #{__FILE__}:#{__LINE__}"; end 
        issue = Issue.find_by_id(issue_id)
        unless issue
          msg = "MailHandler: issue ##{issue.id} does not exists at #{__FILE__}:#{__LINE__}"
          if logger; logger.info msg; end
          msg_failed_receive(@user.email, msg, @email)
          return
        end
        # check permission
        unless @ho[:no_permission_check]
          unless user.allowed_to?(:add_issue_notes, issue.project) ||
                   user.allowed_to?(:edit_issues, issue.project)
            raise UnauthorizedAction
          end
        end

        # ignore CLI-supplied defaults for new issues
        @ho[:issue].clear

        journal = issue.init_journal(user)
        if from_journal && from_journal.private_notes?
          # If the received email was a reply to a private note, make the added note private
          issue.private_notes = true
        end
        issue.safe_attributes = issue_attributes_from_keywords(issue)
        issue.safe_attributes = {'custom_field_values' => custom_field_values_from_keywords(issue)}
        journal.notes = cleaned_up_text_body
        add_attachments(issue)
        issue.save!
        if logger; logger.info "MailHandler: issue ##{issue.id} updated by #{user} (#{email.from.to_a.first.to_s.strip}) at #{__FILE__}:#{__LINE__}"; end
        journal
      end

      def receive_journal_reply_with_tsreceivejournalreply(journal_id)
        if logger; logger.info "MailHandler: receive_journal_reply_with_tsreceivejournalreply at #{__FILE__}:#{__LINE__}"; end 
        journal = Journal.find_by_id(journal_id)
        if journal 
          if journal.journalized_type == 'Issue'
            if logger; logger.info "MailHandler: receive_jornal_reply: journal_id: #{journal_id} at #{__FILE__}:#{__LINE__}"; end
            receive_issue_reply(journal.journalized_id, journal)
          else
            if logger; logger.info "MailHandler: receive_jornal_reply: journal_id: #{journal_id}, jounalized_type != 'Issue' at #{__FILE__}:#{__LINE__}"; end
          end
        else
          if logger; logger.info "MailHandler: receive_jornal_reply: no journal_id: #{journal_id} at #{__FILE__}:#{__LINE__}"; end 
        end
      end

      def receive_message_reply_with_tsreceivemessagereply(message_id)
        if logger; logger.info "MailHandler: receive_message_reply_with_tsreceivemessagereply at #{__FILE__}:#{__LINE__}"; end 
        message = Message.find_by_id(message_id)
        if message
          message = message.root

          unless @ho[:no_permission_check]
            raise UnauthorizedAction unless user.allowed_to?(:add_messages, message.project)
          end

          if !message.locked?
            reply = Message.new(:subject => cleaned_up_subject.gsub(%r{^.*msg\d+\]}, '').strip,
                            :content => cleaned_up_text_body)
            reply.author = user
            reply.board = message.board
            message.children << reply
            add_attachments(reply)
            reply
          else
            msg = "MailHandler: ignoring reply from [#{sender_email}] to a locked topic at #{__FILE__}:#{__LINE__}"
            if logger; logger.info msg; end
            msg_failed_receive(@user.email, msg, @email)
          end
        end
      end

      def add_attachments_with_tsaddattachments(obj)
        if logger; logger.info "MailHandler: add_attachments_with_tsaddattachments at #{__FILE__}:#{__LINE__}"; end 
        if email.attachments && email.attachments.any?
          email.attachments.each do |attachment|
            obj.attachments << Attachment.create(:container => obj,
                                                 :file => attachment.decoded,
                                                 :filename => attachment.filename,
                                                 :author => user,
                                                 :content_type => attachment.mime_type)
          end 
        end 
        if email.html_part
          obj.attachments << Attachment.create(:container => obj,
                                               :file => email.html_part.body.decoded,
                                               :filename => "EMAIL-BODY-#{Date.today.strftime('%Y-%m-%d')}.html",
                                               :author => user,
                                               :content_type => 'text/html')
        end 
      end

      def plain_text_body_with_tsplaintextbody
        #if logger; logger.info "MailHandler: plain_text_body_with_tsplaintextbody at #{__FILE__}:#{__LINE__}"; end 
        return @plain_text_body unless @plain_text_body.nil?
        part = email.text_part || email.html_part || email
        case part.charset
          when 'ks_c_5601-1987'
            pcharset = 'CP949'
          else
            pcharset = part.charset
        end 
        @plain_text_body = Redmine::CodesetUtil.to_utf8(part.body.decoded, pcharset)

        # strip html tags and remove doctype directive
        unless email.text_part
          @plain_text_body = strip_tags(@plain_text_body.strip)
        end 
        @plain_text_body.sub! %r{^<!DOCTYPE .*$}, ''
        @plain_text_body
      end 

	  def cleanup_body_with_tscleanupbody(body)
        #if logger; logger.info "MailHandler: cleanup_body_with_tscleanupbody: body = #{body} at #{__FILE__}:#{__LINE__}"; end 
        if email.text_part.nil? && email.html_part.nil?
          #if logger; logger.info "MailHandler: email.text_part.nil && email.html_part.nil at #{__FILE__}:#{__LINE__}"; end 
          if @email.header['Content-Type'] && !@email.header['Content-Type'].to_s.match(%r{text/(html|plain)})
            if logger; logger.info "MailHandler: cleanup_body: Content-Type = #{@email.header['Content-Type']}, body set empty at #{__FILE__}:#{__LINE__}"; end
            body = ''
          end
        else
          delimiters = Setting.mail_handler_body_delimiters.to_s.split(/[\r\n]+/).reject(&:blank?).map {|s| Regexp.escape(s)}
          #if logger; logger.info "MailHandler: delimiters = #{delimiters.inspect} at #{__FILE__}:#{__LINE__}"; end 
          unless delimiters.empty?
            regex = Regexp.new("^[> ]*(#{ delimiters.join('|') })\s*[\r\n].*", Regexp::MULTILINE)
            body = body.gsub(regex, '') 
          end 
        end 
        body.strip
      end 

      def create_user_from_email_with_tscreateuserfromemail
        if logger; logger.info "MailHandler: create_user_from_email_with_tscreateuserwithemail at #{__FILE__}:#{__LINE__}"; end 
        from = email.header['from'].to_s
        addr, name = from, nil
        if m = from.match(/^"?(.+?)"?\s+<(.+@.+)>$/)
          addr, name = m[2], m[1]
        end
        if addr.present?
          user = self.class.new_user_from_attributes(addr, name)
          if @ho[:no_notification]
            user.mail_notification = 'none'
          end
          if user.save
            user
          else
            if logger; logger.info "MailHandler: failed to create User: #{user.errors.full_messages} at #{__FILE__}:#{__LINE__}"; end
            nil
          end
        else
          if logger; logger.info "MailHandler: failed to create User: no FROM address found at #{__FILE__}:#{__LINE__}"; end
          nil
        end
      end

      def add_user_to_group_with_tsaddusertogroup(default_group)
        if logger; logger.info "MailHandler: add_user_to_group_with_tsaddusertogroup at #{__FILE__}:#{__LINE__}"; end 
        if default_group.present?
          default_group.split(',').each do |group_name|
            if group = Group.named(group_name).first
              group.users << @user
            elsif logger
              logger.info "MailHandler: could not add user to [#{group_name}], group not found at #{__FILE__}:#{__LINE__}"
            end
          end
        end
      end
  end
end
