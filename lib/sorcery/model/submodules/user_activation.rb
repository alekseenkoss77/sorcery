module Sorcery
  module Model
    module Submodules
      # This submodule adds the ability to make the user activate his account via email
      # or any other way in which he can recieve an activation code.
      # with the activation code the user may activate his account.
      # When using this submodule, supplying a mailer is mandatory.
      module UserActivation
        def self.included(base)
          base.sorcery_config.class_eval do
            attr_accessor :activation_state_attribute_name,
                          :activation_code_attribute_name,
                          :sorcery_mailer,
                          :activation_needed_email_method_name,
                          :activation_success_email_method_name,
                          :prevent_non_active_users_to_login
          end
          
          base.sorcery_config.instance_eval do
            @defaults.merge!(:@activation_state_attribute_name => :activation_state,
                             :@activation_code_attribute_name  => :activation_code,
                             :@sorcery_mailer              => nil,
                             :@activation_needed_email_method_name  => :activation_needed_email,
                             :@activation_success_email_method_name => :activation_success_email,
                             :@prevent_non_active_users_to_login => true)
            reset!
          end
          
          base.class_eval do
            before_create :setup_activation
            after_create :send_activation_needed_email!
          end
          
          # make sure a mailer is defined
          post_validation_proc = Proc.new do |config|
            msg = "To use user_activation submodule, you must define a mailer (config.sorcery_mailer = YourMailerClass)."
            raise ArgumentError, msg if config.sorcery_mailer == nil
          end
          base.sorcery_config.add_post_config_validation(post_validation_proc)
          
          # prevent or allow the login of non-active users
          pre_authenticate_proc = Proc.new do |user, config|
            config.prevent_non_active_users_to_login ? user.send(config.activation_state_attribute_name) == "active" : true
          end
          base.sorcery_config.add_pre_authenticate_validation(pre_authenticate_proc)
          
          base.send(:include, InstanceMethods)
        end
        
        module InstanceMethods
          def activate!
            config = sorcery_config
            self.send(:"#{config.activation_code_attribute_name}=", nil)
            self.send(:"#{config.activation_state_attribute_name}=", "active")
            send_activation_success_email!
          end

          protected

          def setup_activation
            config = sorcery_config
            generated_activation_code = CryptoProviders::SHA1.encrypt( Time.now.to_s.split(//).sort_by {rand}.join )
            self.send(:"#{config.activation_code_attribute_name}=", generated_activation_code)
            self.send(:"#{config.activation_state_attribute_name}=", "pending")
          end

          def send_activation_needed_email!
            generic_send_email(:activation_needed_email_method_name)
          end

          def send_activation_success_email!
            generic_send_email(:activation_success_email_method_name)
          end
        end
      end
    end
  end
end