#get '/issue_statuses/:id/change_issue_text', to: 'issue_statuses#change_issue_text' 
#resources :issue_statuses do
  #collection do
  #  get 'change_issue_text_after'
  #end
  #get 'change_issue_text_after', on: :collection
#end
RedmineApp::Application.routes.draw do
  match '/changeauthor/index', :to => 'changeauthor#index'
  match '/changeauthor/edit', :to => 'changeauthor#edit'
end 

get '/issue_statuses/:id/change_issue_text_after', to: 'issue_statuses#change_issue_text_after', as: 'change_issue_text_after_issue_statuses'
