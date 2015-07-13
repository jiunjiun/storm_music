class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, #:registerable, :recoverable,
         :rememberable, :trackable, :validatable,
         :omniauthable, :omniauth_providers => [:soundcloud]

  def uid
    identity.uid
  end

  def self.find_for_oauth(auth, signed_in_resource = nil)
    # Rails.logger.debug { " -- #{auth.credentials.token}" }

    # Get the identity and user if they exist
    identity = Identity.find_for_oauth(auth)

    # If a signed_in_resource is provided it always overrides the existing user
    # to prevent the identity being locked with accidentally created accounts.
    # Note that this may leave zombie accounts (with no associated identity) which
    # can be cleaned up at a later date.
    user = signed_in_resource ? signed_in_resource : identity.user

    # Create the user if needed
    if user.nil?

      # Get the existing user by email if the provider gives us a verified email.
      # If no verified email was provided we assign a temporary email and ask the
      # user to verify it on the next step via UsersController.finish_signup
      email_is_verified = nil

      case auth.provider
      when 'facebook'
        email_is_verified = auth.info.email && (auth.info.verified || auth.info.verified_email)
      when 'google_oauth2'
        email_is_verified = auth.info.email
      when 'soundcloud'
      end

      email = auth.info.email if email_is_verified
      user = User.where(email: email).first if email

      # Create the user if it's a new registration
      if user.nil?
        user = User.new(
          name: auth.info.name,
          username: auth.info.nickname || auth.uid,
          email: email ? email : "#{auth.uid}@#{auth.provider}.com",
          password: Devise.friendly_token[0,20]
        )

        # user.skip_confirmation!
        user.save!
      end
    end

    # Update Token
    identity.token = auth.credentials.token
    identity.save!

    # Associate the identity with the user if needed
    if identity.user != user
      identity.user = user
      identity.save!
    end
    user
  end
end
