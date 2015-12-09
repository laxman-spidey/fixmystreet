package FixMyStreet::App::Controller::Auth;
use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller'; }

use Email::Valid;
use Net::Domain::TLD;
use mySociety::AuthToken;
use JSON::MaybeXS;
use Net::Facebook::Oauth2;
use Net::Twitter::Lite::WithAPIv1_1;

=head1 NAME

FixMyStreet::App::Controller::Auth - Catalyst Controller

=head1 DESCRIPTION

Controller for all the authentication related pages - create account, sign in,
sign out.

=head1 METHODS

=head2 index

Present the user with a sign in / create account page.

=cut

sub general : Path : Args(0) {
    my ( $self, $c ) = @_;

    $c->detach( 'redirect_on_signin', [ $c->get_param('r') ] )
        if $c->user && $c->get_param('r');

    # all done unless we have a form posted to us
    return unless $c->req->method eq 'POST';

    # decide which action to take
    my $clicked_password = $c->get_param('sign_in');
    my $clicked_email = $c->get_param('email_sign_in');
    my $data_password = $c->get_param('password_sign_in');
    my $data_email = $c->get_param('name') || $c->get_param('password_register');

    $c->detach('email_sign_in') if $clicked_email || ($data_email && !$data_password);

       $c->forward( 'sign_in' )
    && $c->detach( 'redirect_on_signin', [ $c->get_param('r') ] );

}

sub general_test : Path('_test_') : Args(0) {
    my ( $self, $c ) = @_;
    $c->stash->{template} = 'auth/token.html';
}

=head2 sign_in

Allow the user to sign in with a username and a password.

=cut

sub sign_in : Private {
    my ( $self, $c, $email ) = @_;

    $email ||= $c->get_param('email') || '';
    my $password = $c->get_param('password_sign_in') || '';
    my $remember_me = $c->get_param('remember_me') || 0;

    # Sign out just in case
    $c->logout();

    if (   $email
        && $password
        && $c->authenticate( { email => $email, password => $password } ) )
    {

        # unless user asked to be remembered limit the session to browser
        $c->set_session_cookie_expire(0)
          unless $remember_me;

        return 1;
    }

    $c->stash(
        sign_in_error => 1,
        email => $email,
        remember_me => $remember_me,
    );
    return;
}

=head2 email_sign_in

Email the user the details they need to sign in. Don't check for an account - if
there isn't one we can create it when they come back with a token (which
contains the email addresss).

=cut

sub email_sign_in : Private {
    my ( $self, $c ) = @_;

    # check that the email is valid - otherwise flag an error
    my $raw_email = lc( $c->get_param('email') || '' );

    my $email_checker = Email::Valid->new(
        -mxcheck  => 1,
        -tldcheck => 1,
        -fqdn     => 1,
    );

    my $good_email = $email_checker->address($raw_email);
    if ( !$good_email ) {
        $c->stash->{email} = $raw_email;
        $c->stash->{email_error} =
          $raw_email ? $email_checker->details : 'missing';
        return;
    }

    my $user_params = {};
    $user_params->{password} = $c->get_param('password_register')
        if $c->get_param('password_register');
    my $user = $c->model('DB::User')->new( $user_params );

    my $token_obj = $c->model('DB::Token')    #
      ->create(
        {
            scope => 'email_sign_in',
            data  => {
                email => $good_email,
                r => $c->get_param('r'),
                name => $c->get_param('name'),
                password => $user->password,
            }
        }
      );

    $c->stash->{token} = $token_obj->token;
    $c->send_email( 'login.txt', { to => $good_email } );
    $c->stash->{template} = 'auth/token.html';
}

=head2 token

Handle the 'email_sign_in' tokens. Find the account for the email address
(creating if needed), authenticate the user and delete the token.

=cut

sub token : Path('/M') : Args(1) {
    my ( $self, $c, $url_token ) = @_;

    # retrieve the token or return
    my $token_obj = $url_token
      ? $c->model('DB::Token')->find( {
          scope => 'email_sign_in', token => $url_token
        } )
      : undef;

    if ( !$token_obj ) {
        $c->stash->{token_not_found} = 1;
        return;
    }

    if ( $token_obj->created < DateTime->now->subtract( days => 1 ) ) {
        $c->stash->{token_not_found} = 1;
        return;
    }

    # Sign out in case we are another user
    $c->logout();

    # find or create the user related to the token.
    my $data = $token_obj->data;
    my $user = $c->model('DB::User')->find_or_create( { email => $data->{email} } );
    $user->name( $data->{name} ) if $data->{name};
    $user->password( $data->{password}, 1 ) if $data->{password};
    $user->update;
    $c->authenticate( { email => $user->email }, 'no_password' );

    # send the user to their page
    $c->detach( 'redirect_on_signin', [ $data->{r} ] );
}

=head2 social_signup

Asks the user to confirm data returned from facebook/twitter and signs up the user.
TODO: user to-be information is received in the session. i'm sure there is a better way to do this :(

=cut

sub social_signup : Path('/auth/social_signup') : Args(0) {
	my ( $self, $c ) = @_;

	my $name = $c->req->param('name') if $c->req->param('name');
	my $email = $c->req->param('email') if $c->req->param('email');
	my $password = $c->req->param('password') if $c->req->param('password');
	my $phone = $c->req->param('phone') if $c->req->param('phone');
	my $facebook_id = $c->req->param('facebook_id') if $c->req->param('facebook_id');
	my $twitter_id = $c->req->param('twitter_id') if $c->req->param('twitter_id');

	my $new_user = $c->model('DB::User')->new({
		name => $name,
		email => $email,
		phone => $phone,
		facebook_id => $facebook_id,
		twitter_id => $twitter_id,
	});

	$c->stash->{user} = $new_user;

	$c->stash->{field_errors} ||= {};
	my %field_errors = $c->cobrand->user_check_for_errors( $c );

	if ( !scalar keys %field_errors ) {
		my $user = $c->model('DB::User')->find_or_create({ email => $new_user->email });

		if ( $user ) {
			my $token_data = {
				id => $user->id,
				facebook_id => $new_user->facebook_id,
				twitter_id => $new_user->twitter_id,
				name => $new_user->name,
				email => $new_user->email,
				#password => $password,
				phone => $new_user->phone,
			};
			if ( $password ) {
				$token_data->{password} = $password;
			}

			my $token_social_sign_up = $c->model("DB::Token")->create( {
				scope => 'email_sign_in/social',
				data => {
					%$token_data,
					return_url => $c->session->{oauth}{return_url},
					detach_to => $c->session->{oauth}{detach_to},
					detach_args => $c->session->{oauth}{detach_args},
				}
			} );

			$c->stash->{token} = $token_social_sign_up->token;
			$c->send_email( 'login.txt', { to => $new_user->email } );
			$c->stash->{template} = 'auth/token.html';
		}
	} else {
		$c->stash->{field_errors} = \%field_errors;
	}
}

=head2 facebook_sign_in

Starts the Facebook authentication sequence.

=cut

sub facebook_sign_in : Private {
	my( $self, $c ) = @_;

	my $params = $c->req->parameters;

    my $facebook_app_id = mySociety::Config::get('FACEBOOK_APP_ID', undef);
    my $facebook_app_secret = mySociety::Config::get('FACEBOOK_APP_SECRET', undef);
    my $facebook_callback_url = $c->uri_for('/auth/Facebook');
 
	my $fb = Net::Facebook::Oauth2->new(
		application_id => $facebook_app_id,  ##get this from your facebook developers platform
		application_secret => $facebook_app_secret, ##get this from your facebook developers platform
		callback => $facebook_callback_url,  ##Callback URL, facebook will redirect users after authintication
	);
 
	##there is no verifier code passed so let's create authorization URL and redirect to it
	my $url = $fb->get_authorization_url(
		scope => ['email'], ###pass scope/Extended Permissions params as an array telling facebook how you want to use this access
		display => 'page' ## how to display authorization page, other options popup "to display as popup window" and wab "for mobile apps"
	);

	my %oauth;
	$oauth{'return_url'} = $c->req->param('r');
	$oauth{'detach_to'} = $c->stash->{detach_to};
	$oauth{'detach_args'} = $c->stash->{detach_args};
	#Sync accounts
	$oauth{'facebook_link'} = $c->req->param('facebook_link') if ( $c->req->param('facebook_link') );

	###save this token in session
	$c->session->{oauth} = \%oauth;

	$c->res->redirect($url);
}

=head2 facebook_callback

Handles the Facebook callback request and completes the authentication sequence.

=cut

sub facebook_callback: Path('/auth/Facebook') : Args(0) {
	my( $self, $c ) = @_;

	my $params = $c->req->parameters;

	if ( $params->{error_code} ) {
		#Redirect to error page...
		$c->set_session_cookie_expire(0);

		#$c->res->redirect( $c->uri_for( "/" ) );

		$c->stash->{message} = 'No es posible iniciar la sesi&oacute;n en Facebook. Por favor vuelva a intetarlo m&aacute;s tarde.';
		$c->stash->{template} = 'errors/generic.html';
	}
	else {
		my $facebook_app_id = mySociety::Config::get('FACEBOOK_APP_ID', undef);
		my $facebook_app_secret = mySociety::Config::get('FACEBOOK_APP_SECRET', undef);
		my $facebook_callback_url = $c->uri_for('/auth/Facebook');

		my $fb = Net::Facebook::Oauth2->new(
			application_id => $facebook_app_id,  ##get this from your facebook developers platform
			application_secret => $facebook_app_secret, ##get this from your facebook developers platform
			callback => $facebook_callback_url,  ##Callback URL, facebook will redirect users after authintication
		);

		# you need to pass the verifier code to get access_token
		my $access_token = $fb->get_access_token( code => $params->{code} );

		# save this token in session
		$c->session->{oauth}{token} =  $access_token;

		my $info2 = $fb->get('https://graph.facebook.com/me/permissions')->as_hash();
		my $info = $fb->get('https://graph.facebook.com/me')->as_hash();

		my $name = $info->{'name'};
		my $email = $info->{'email'};
		my $uid = $info->{'id'};
		my $user = $c->model('DB::User')->find( { facebook_id => $uid } );
		$c->log->debug('FB CALLBACK FIND');
		if (!$user) {
			$c->log->debug('FB CALLBACK NO USER');
			if( $c->session->{oauth}{facebook_link} and $c->user ){
				$c->log->debug('FB CALLBACK ACTUALIZA');
				$c->user->facebook_id($uid);
				$c->user->update();
				#Redirect to my
				my $uri = $c->uri_for( '/my', { mf1 => 1 } );
			    $c->res->redirect( $uri );
			    $c->detach;
			}
			else{
				$c->log->debug('FB CALLBACK NUEVO');
				my $new_user = $c->model('DB::User')->new({
					name => $name,
					email => $email,
					facebook_id => $uid,
				});
				$c->stash->{user} = $new_user;
				$c->stash->{template} = 'auth/social_signup.html';
			}
		}
		else {
			$c->log->debug('FB CALLBACK USER');
			if( $c->session->{oauth}{facebook_link} and $c->user ){
				$c->log->debug('FB CALLBACK REDIRECT HAY OTRO USER');
				my $uri = $c->uri_for( '/my', { mf2 => 1 } );
			    $c->res->redirect( $uri );
			    $c->detach;
			}
			else {
				$c->log->debug('FB CALLBACK FUE PARA AUTENTICAR');
				#Autenthicate user with immedate expire
				$c->authenticate( { email => $user->email }, 'no_password' );
				$c->set_session_cookie_expire(0);
				if ($c->session->{oauth}{detach_to}){
					$c->detach($c->session->{oauth}{detach_to}, $c->session->{oauth}{detach_args});
				}
				else{
					$c->detach( 'redirect_on_signin', [ $c->session->{oauth}{return_url} ] );
				}
			}
		}
	}
}

=head2 twitter_sign_in

Starts the Twitter authentication sequence.

=cut

sub twitter_sign_in : Private {
   my( $self, $c ) = @_;
    my $twitter_key = $c->config->{TWITTER_KEY};
    my $twitter_secret = $c->config->{TWITTER_SECRET};
    my $twitter_callback_url = $c->uri_for('/auth/Twitter');

   my %consumer_tokens = (
       consumer_key    => $twitter_key,
       consumer_secret => $twitter_secret,
   );

   my $twitter = Net::Twitter::Lite::WithAPIv1_1->new(ssl => 1, %consumer_tokens);
    my $url = $twitter->get_authorization_url(callback => $twitter_callback_url);

   my %oauth;
   $oauth{'return_url'} = $c->get_param('r');
   $oauth{'detach_to'} = $c->stash->{detach_to};
   $oauth{'detach_args'} = $c->stash->{detach_args};
   $oauth{'token'} = $twitter->request_token;
   $oauth{'token_secret'} = $twitter->request_token_secret;
   #Sync accounts
   $oauth{'twitter_link'} = $c->get_param('twitter_link') if ($c->get_param('twitter_link'));

   ###save this token in session
   $c->session->{oauth} = \%oauth;
   $c->res->redirect($url);
}

=head2 twitter_callback

Handles the Twitter callback request and completes the authentication sequence.

=cut

sub twitter_callback: Path('/auth/Twitter') : Args(0) {
   my( $self, $c ) = @_;
   my $request_token = $c->get_param('oauth_token');
    my $verifier      = $c->get_param('oauth_verifier');

    my $twitter_key = $c->config->{TWITTER_KEY};
    my $twitter_secret = $c->config->{TWITTER_SECRET};

    my %consumer_tokens = (
       consumer_key    => $twitter_key,
       consumer_secret => $twitter_secret,
   );

   my $oauth = $c->session->{oauth};

   my $twitter = Net::Twitter::Lite::WithAPIv1_1->new(ssl => 1, %consumer_tokens);
   $twitter->request_token($oauth->{token});
   $twitter->request_token_secret($oauth->{token_secret});

   my($access_token, $access_token_secret, $uid, $name) =
       $twitter->request_access_token(verifier => $verifier);

   my $twitter_user = $twitter->show_user($uid);
   my $user = $c->model('DB::User')->find( { twitter_id => $uid } );

   if (!$user) {
       if( $oauth->{twitter_link} and $c->user ){
           #Actualizamos la foto en caso que se quiera
           $c->user->twitter_id($uid);
           $c->user->update();
           #Redirect to my
           my $uri = $c->uri_for( '/my', { mt1 => 1 } );
           $c->res->redirect( $uri );
           $c->detach;
       }
       else{
           my $new_user = $c->model('DB::User')->new({
               name => $name,
               twitter_id => $uid,
           });

           $c->stash->{user} = $new_user;
           $c->stash->{template} = 'auth/social_signup.html';
       }
   }
   else {
       if( $oauth->{twitter_link} and $c->user ){
           my $uri = $c->uri_for( '/my', { mt2 => 1 } );
           $c->res->redirect( $uri );
           $c->detach;
       }
       else {
           #Autenthicate user with immedate expire
           $c->authenticate( { email => $user->email }, 'no_password' );
           $c->set_session_cookie_expire(0);
           if ($c->session->{oauth}{detach_to}){
               $c->detach($c->session->{oauth}{detach_to}, $c->session->{oauth}{detach_args});
           }
           else{
               $c->detach( 'redirect_on_signin', [ $c->session->{oauth}{return_url} ] );
           }
       }
   }
}

=head2 redirect_on_signin

Used after signing in to take the person back to where they were.

=cut


sub redirect_on_signin : Private {
    my ( $self, $c, $redirect ) = @_;
    $redirect = 'my' unless $redirect;
    if ( $c->cobrand->moniker eq 'zurich' ) {
        $redirect = 'my' if $redirect eq 'admin';
        $redirect = 'admin' if $c->user->from_body;
    }
    $c->res->redirect( $c->uri_for( "/$redirect" ) );
}

=head2 redirect

Used when trying to view a page that requires sign in when you're not.

=cut

sub redirect : Private {
    my ( $self, $c ) = @_;

    my $uri = $c->uri_for( '/auth', { r => $c->req->path } );
    $c->res->redirect( $uri );
    $c->detach;

}

=head2 change_password

Let the user change their password.

=cut

sub change_password : Local {
    my ( $self, $c ) = @_;

    $c->detach( 'redirect' ) unless $c->user;

    # FIXME - CSRF check here
    # FIXME - minimum criteria for passwords (length, contain number, etc)

    # If not a post then no submission
    return unless $c->req->method eq 'POST';

    # get the passwords
    my $new = $c->get_param('new_password') // '';
    my $confirm = $c->get_param('confirm') // '';

    # check for errors
    my $password_error =
       !$new && !$confirm ? 'missing'
      : $new ne $confirm ? 'mismatch'
      :                    '';

    if ($password_error) {
        $c->stash->{password_error} = $password_error;
        $c->stash->{new_password}   = $new;
        $c->stash->{confirm}        = $confirm;
        return;
    }

    # we should have a usable password - save it to the user
    $c->user->obj->update( { password => $new } );
    $c->stash->{password_changed} = 1;

}

=head2 sign_out

Log the user out. Tell them we've done so.

=cut

sub sign_out : Local {
    my ( $self, $c ) = @_;
    $c->logout();
}

sub ajax_sign_in : Path('ajax/sign_in') {
    my ( $self, $c ) = @_;

    my $return = {};
    if ( $c->forward( 'sign_in' ) ) {
        $return->{name} = $c->user->name;
    } else {
        $return->{error} = 1;
    }

    my $body = encode_json($return);
    $c->res->content_type('application/json; charset=utf-8');
    $c->res->body($body);

    return 1;
}

sub ajax_sign_out : Path('ajax/sign_out') {
    my ( $self, $c ) = @_;

    $c->logout();

    my $body = encode_json( { signed_out => 1 } );
    $c->res->content_type('application/json; charset=utf-8');
    $c->res->body($body);

    return 1;
}

sub ajax_check_auth : Path('ajax/check_auth') {
    my ( $self, $c ) = @_;

    my $code = 401;
    my $data = { not_authorized => 1 };

    if ( $c->user ) {
        $data = { name => $c->user->name };
        $code = 200;
    }

    my $body = encode_json($data);
    $c->res->content_type('application/json; charset=utf-8');
    $c->res->code($code);
    $c->res->body($body);

    return 1;
}

=head2 check_auth

Utility page - returns a simple message 'OK' and a 200 response if the user is
authenticated and a 'Unauthorized' / 401 reponse if they are not.

Mainly intended for testing but might also be useful for ajax calls.

=cut

sub check_auth : Local {
    my ( $self, $c ) = @_;

    # choose the response
    my ( $body, $code )    #
      = $c->user
      ? ( 'OK', 200 )
      : ( 'Unauthorized', 401 );

    # set the response
    $c->res->body($body);
    $c->res->code($code);

    # NOTE - really a 401 response should also contain a 'WWW-Authenticate'
    # header but we ignore that here. The spec is not keeping up with usage.

    return;
}

__PACKAGE__->meta->make_immutable;

1;
