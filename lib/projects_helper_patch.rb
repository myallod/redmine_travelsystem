module ProjectsHelperPatch
  #module InstanceMethods
  #  def render_project_hierarchy(projects)
  #    render_project_nested_lists(projects) do |project|
  #      s = link_to_project(project, {}, :class => "#{project.css_classes} #{User.current.member_of?(project) ? 'my-project' : nil}")
  #      s
  #    end
  #  end
  #end

  def self.included(receiver)
    #receiver.send(:include, InstanceMethods)

    receiver.class_eval do
      def render_project_hierarchy(projects)
        render_project_nested_lists(projects) do |project|
          s = link_to_project(project, {}, :class => "#{project.css_classes} #{User.current.member_of?(project) ? 'my-project' : nil}")
          s
        end
      end
    end
  end
end
