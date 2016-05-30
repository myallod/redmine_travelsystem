class AddIssueChangeStatusTextMessage < ActiveRecord::Migration
  def self.up
    add_column :issue_statuses, :text_message, :string, :limit => 255, :default => ''
  end

  def self.down
    remove_column :issue_statuses, :text_message
  end
end
