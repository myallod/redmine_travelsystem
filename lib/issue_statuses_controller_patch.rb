module IssueStatusesControllerPatch
  def self.included(base)
    base.send(:include, InstanceMethods)
  end

  module InstanceMethods
    def change_issue_text_after
      render :q	
      #redirect_to issue_statuses_path
    end
  end
end
