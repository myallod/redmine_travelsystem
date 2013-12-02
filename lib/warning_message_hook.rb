module RedmineTravelsystem
  module Hooks
    class LayoutHook < Redmine::Hook::ViewListener
      def view_layouts_base_sidebar(context={})
        if File.open(File.join(Rails.root, "lib/redmine/plugin.rb")).read().include? "::I18n.load_path"
          context[:controller].send(:flash)[:warning] = l(:text_plugin_not_usable)
        end
      end
    end
  end
end
#render_on :view_layout_base_sidebar, :partial => 'show_warning'
