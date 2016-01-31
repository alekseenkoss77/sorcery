module Sorcery
  module Providers
    # This class adds support for OAuth with vk.com.
    #
    #   config.mailru.key = <key>
    #   config.mailru.secret = <secret>
    #   ...
    #
    class Mailru < Base
      include Protocols::Oauth2

      attr_accessor :auth_path, :token_path, :user_info_url, :scope, :response_type

      def initialize
        super

        @scope          = nil
        @site           = 'https://connect.mail.ru/'
        @user_info_url  = 'http://www.appsmail.ru/platform/api'
        @auth_path      = '/oauth/authorize'
        @token_path     = '/oauth/token'
        @grant_type     = 'authorization_code'
      end

      def get_user_hash(access_token)
        user_hash = auth_hash(access_token)

        params = {
          app_id: key,
          method: 'users.getInfo',
          secure: 1,
          session_key: access_token.token,
          uids: access_token.params['x_mailru_vid']
        }

        request_params = params.merge(
          sig: sign_params(params),
        )
        
        response = access_token.get(user_info_url, params: request_params)
        
        if user_hash[:user_info] = JSON.parse(response.body)
          user_hash[:user_info] = user_hash[:user_info].first
          user_hash[:user_info]['full_name'] = [user_hash[:user_info]['first_name'], user_hash[:user_info]['last_name']].join(' ')
          user_hash[:uid] = user_hash[:user_info]['uid']
        end
        user_hash
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(params, session)
        self.authorize_url({ authorize_url: auth_path,  })
      end

      def process_callback(params, session)
        args = {}.tap do |a|
          a[:code] = params[:code] if params[:code]
        end

        get_access_token(args, token_url: token_path, token_method: :post)
      end

      private

      def sign_params(params)
        code = params.map { |k,v| "#{k}=#{v}" }.join
        Digest::MD5.hexdigest(code + secret)
      end
    end
  end
end
