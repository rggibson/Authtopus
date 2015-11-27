import logging
import json
import os
import re
import httplib

from google.appengine.api import urlfetch

import endpoints
from endpoints import UnauthorizedException, BadRequestException
from endpoints import NotFoundException, ServiceException

from google.appengine.ext import ndb

from protorpc import remote # API
from protorpc import message_types

from endpoints_proto_datastore.ndb import EndpointsModel

from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError

from urllib import urlencode

from .models import User

PROVIDER_URLS = dict( facebook=( 'https://graph.facebook.com/me'
                                 + '?fields=id,email&{0}' ),
                      google=( 'https://www.googleapis.com/oauth2/v1/'
                               + 'userinfo?{0}' ) )

class ConflictException( ServiceException ):
    """Conflict exception that is mapped to a 409 response."""
    http_status = httplib.CONFLICT
    
@endpoints.api( name='auth', version='v1.0' )
class Auth( remote.Service ):

    # Constants
    USER_RE = re.compile( r"^[a-zA-Z0-9_-]{1,20}$" )
    PASS_RE = re.compile( r"^.{4,20}$" )
    EMAIL_RE = re.compile( r"^[\S]+@[\S]+\.[\S]+$" )
    
    # Class Methods
    @classmethod
    def valid_username( cls, username ):
        """ Checks if a username is acceptable

        :param username:
            The username to check
        :returns:
            A (boolean, string) tuple where the boolean indicates if the
            username is acceptable, and if not, msg says why it is not
            acceptable.
        """
        if username and cls.USER_RE.match( username ):
            return True, None
        else:
            return False, ( 'Usernames must be 1-20 characters long and may '
                            + 'only consist of letters, numbers, underscores,'
                            + ' and dashes' )
    
    @classmethod
    def valid_password( cls, password_raw ):
        """ Checks if a password_raw is acceptable

        :param password_raw:
            The raw password to check
        :returns:
            A (boolean, string) tuple where the boolean indicates if the
            raw password is acceptable, and if not, msg says why it is not
            acceptable.
        """
        if password_raw and cls.PASS_RE.match( password_raw ):
            return True, None
        else:
            return False, 'Passwords must be 4-20 characters in length'
        
    @classmethod
    def valid_email( cls, email ):
        """ Checks if an email address is acceptable

        :param email:
            The email address to check
        :returns:
            A (boolean, string) tuple where the boolean indicates if the
            email address is acceptable, and if not, msg says why it is not
            acceptable.
        """
        if email and cls.EMAIL_RE.match( email ):
            return True, None
        else:
            return False, ( "Email addresses must contain an '@' followed by a"
                            + " '.' with some characters before and after "
                            + "each" )

    @classmethod
    def get_current_user_id( cls ):
        """ Retreives the user_id for the logged in user

        :returns:
            A tuple of length 2 where the first entry is the currently
            logged in user's user_id and the second entry is the auth_token,
            or None, None if no user logged in.
        """
        # Get auth information from the request header
        user_id_auth_token = os.getenv( 'HTTP_AUTHORIZATION' )
        if user_id_auth_token:
            # Retreive the user_id and auth token
            parts = user_id_auth_token.split( ':' )
            if len( parts ) < 2:
                return None, None
            user_id = None
            try:
                user_id = int( parts[ 0 ] )
            except ValueError:
                return None, None
            auth_token = ':'.join( parts[ 1: ] )

            if User.validate_auth_token( user_id, auth_token ):
                return user_id, auth_token
            else:
                return None, None
        else:
            return None, None

    @classmethod
    def get_current_user( cls, verified_email_required=True ):
        """ Retreives the User object for the logged in user

        :returns:
            The currently logged in user's User object, or None if
            no user logged in.
        """
        # Get auth information from the request header
        user_id, _ = cls.get_current_user_id( )
        if user_id is not None:
            user = User.get_by_id( user_id )
            if user.email_verified or not verified_email_required:
                return user
            else:
                return None
        else:
            return None

    @classmethod
    def protected_get_user_by_username( cls, username ):
        """ Retreives the User object for the given username, provided the
            username is that of the currently logged in user, or the
            currently logged in user is a mod.

        :param username:
            The username of the user to get
        :returns:
            The appropriate User object, or None if the user does not exist
            or the logged in user does not have authorization.
        """
        if not username:
            return None
        current_user = cls.get_current_user( verified_email_required=False )
        if current_user is None:
            return None
        elif current_user.username_lower == username.lower( ):
            return current_user
        elif current_user.is_mod:
            return User.get_by_username( username )
        else:
            return None

    @classmethod
    def get_local_auth_id( cls, username_or_email ):
        """ Gets an auth id for a user from a username or email address
        """
        return 'local:' + username_or_email.lower( )

    @classmethod
    def create_user_id_auth_token( cls, user_id ):
        """ Creates an auth token for the user

        :param user_id:
            The id of the user requesting the token
        :returns:
            Auth token for the user to authorize themself with on success,
            or None on failure.
        """
        auth_token = User.create_auth_token( user_id )
        if auth_token is None:
            return None
        else:
            return '{0}:{1}'.format( user_id, auth_token )

    @classmethod
    def update_user_internal( cls, user, email, username, password=None,
                              verification_url=None ):
        """ Updates a user with new email, username and password

        :param user:
            The user object to update
        :param email:
            New pending email for the user (can be same as user.email_*)
        :param username:
            New username for the user (can be same as user.username)
        :param password:
            New password for the user (or None to leave password unchanged)
        :param verification_url:
            URL to send email verification when email is changed
        :returns:
            On success, (True, user) and on failure, (False, msg)
        """
        username_auth_id = cls.get_local_auth_id( user.username )
        old_email_pending_lower = user.email_pending_lower
        if( old_email_pending_lower
            and old_email_pending_lower != user.email_verified_lower ):
            email_auth_id = cls.get_local_auth_id( old_email_pending_lower )
        else:
            email_auth_id = None
        ok, info = user.update( email, username, password )
        if ok:
            user = info
        else:
            msg = '|'.join( [ key + ':Already in use' for key in info ] )
            return False, msg

        if user.password:
            # Update local auth_ids
            change_auth_ids = [ ]
            new_username_auth_id = cls.get_local_auth_id( user.username )
            if( new_username_auth_id not in user.auth_ids ):
                change_auth_ids.append( ( username_auth_id,
                                          new_username_auth_id ) )
            if user.email_pending:
                new_email_auth_id = cls.get_local_auth_id( user.email_pending )
                if( new_email_auth_id not in user.auth_ids ):
                    change_auth_ids.append( ( email_auth_id,
                                              new_email_auth_id ) )
            for old_auth_id, new_auth_id in change_auth_ids:
                if old_auth_id:
                    user.remove_auth_id( old_auth_id )
                ok, info = user.add_auth_id( new_auth_id )
                if not ok:
                    logging.error( 'Failed to add new auth id [' + new_auth_id
                                   + ']' )
        
        if( old_email_pending_lower != user.email_pending_lower
            and user.email_pending_lower != user.email_verified_lower ):
            # Resend email verification
            if verification_url:
                user.send_email_verification( verification_url )
            else:
                logging.error( 'No verification url provided when updating'
                               + ' user with new username: ' + username )

        return True, user

    @classmethod
    def validate_email_internal( cls, user ):
        """ Validates a user's pending email address + updates auth ids

        :param user:
            The user object whose email we are validating
        :returns:
            user
        """
        if user.email_verified_lower:
            email_auth_id = cls.get_local_auth_id( user.email_verified_lower )
        else:
            email_auth_id = None
        user = user.validate_email( )

        if user.email_verified_lower:
            new_email_auth_id = cls.get_local_auth_id(
                user.email_verified_lower )
        else:
            new_email_auth_id = None
        
        if( user.password and email_auth_id
            and email_auth_id != new_email_auth_id ):
            # Remove old email auth id
            user.remove_auth_id( email_auth_id )
        
        return user
        
            
    @User.method( request_fields=( 'id', ), # Placeholder field, ignored
                  path='current_user', http_method='GET', name='current_user' )
    def CurrentUser( self, user_msg ):
        user = self.get_current_user( verified_email_required=False )
        if user is None:
            raise UnauthorizedException( 'Invalid credentials' )

        return user

    @User.method( request_fields=( 'username', ),
                  path='get_user', http_method='GET', name='get_user' )
    def GetUser( self, user_msg ):
        # First, get the current user
        current_user = self.get_current_user( verified_email_required=False )
        if current_user is None:
            raise UnauthorizedException( 'Invalid credentials' )

        if current_user.username == user_msg.username:
            return current_user
        elif current_user.is_mod:
            # Validate request params
            ok, msg = self.valid_username( user_msg.username )
            if not ok:
                raise BadRequestException( 'No or invalid username provided' )
        
            user = User.get_by_username( user_msg.username )
            if user is None:
                raise NotFoundException( 'No user exists for username '
                                         + user_msg.username )
            return user
        else:
            raise UnauthorizedException( 'Insufficient privilages' )

    class UpdateUserMessage( EndpointsModel ):
        old_username = ndb.StringProperty( )
        email = ndb.StringProperty( )
        username = ndb.StringProperty( )
        old_password = ndb.StringProperty( )
        password = ndb.StringProperty( )
        verification_url = ndb.StringProperty( )

    @UpdateUserMessage.method( response_fields=( 'email', 'username', ),
                               path='update_user', http_method='POST',
                               name='update_user' )
    def UpdateUser( self, spm ):
        user = self.protected_get_user_by_username( spm.old_username )
        if user is None:
            raise UnauthorizedException( "Cannot edit profile of other user!" )
            
        # Make sure new request params are acceptable
        invalid_params = dict( )
        ok, msg = self.valid_username( spm.username )
        if not ok:
            invalid_params['username'] = msg
        if spm.password is not None and len( spm.password ) > 0:
            if not user.check_password( spm.old_password ):
                invalid_params['old_password'] = 'Invalid password'
            ok, msg = self.valid_password( spm.password )
            if not ok:
                invalid_params['new_password'] = msg
        ok, msg = self.valid_email( spm.email )
        if not ok:
            invalid_params['email'] = msg
        if not spm.verification_url:
            invalid_params['verification_url'] = (
                'A verification url is required' )
        if len( invalid_params.keys( ) ) > 0:
            raise BadRequestException( '|'.join(
                [ key + ':' + invalid_params[ key ]
                  for key in invalid_params.keys( ) ] ) )

        # Update the user
        ok, info = self.update_user_internal( user, spm.email, spm.username,
                                              spm.password,
                                              spm.verification_url )
        if not ok:
            raise ConflictException( info )
                    
        return spm
            
        
    class RegisterMessage( EndpointsModel ):
        email = ndb.StringProperty( )
        username = ndb.StringProperty( )
        password = ndb.StringProperty( )
        verification_url = ndb.StringProperty( )

    @RegisterMessage.method( path='register', http_method='POST',
                             name='register' )
    def Register( self, rm ):
        # Validate request params
        invalid_params = dict( )
        ok, msg = self.valid_username( rm.username )
        if not ok:
            invalid_params['username'] = msg
        ok, msg = self.valid_password( rm.password )
        if not ok:
            invalid_params['password'] = msg
        ok, msg = self.valid_email( rm.email )
        if not ok:
            invalid_params['email'] = msg
        if not rm.verification_url:
            invalid_params['verification_url'] = (
                'A verification url is required' )
        if len( invalid_params.keys( ) ) > 0:
            # Some params were invalid.  Return 400 response.            
            raise BadRequestException( '|'.join(
                [ key + ':' + invalid_params[ key ]
                  for key in invalid_params.keys( ) ] ) )
        
        # Create the user with username auth id
        auth_id = self.get_local_auth_id( rm.username )
        ok, info = User.create_user(
            auth_id,
            password_raw = rm.password,
            unique_properties=['email_pending', 'username',],
            email_pending=rm.email,
            username=rm.username,
            is_mod=False )
        if ok:
            # Success.  Add email auth id so that user can sign in
            # by email too
            user = info
            auth_id = self.get_local_auth_id( user.email_pending )
            ok, info = user.add_auth_id( auth_id )
            if not ok:
                logging.error( 'Failed to add email auth id [' + auth_id
                               + ' ] to username [' + user.username + ']' )

            # Send email verification
            user.send_email_verification( rm.verification_url )
        else:
            # Failed to create new user.  Respond with conflicting properties
            # separated by a colon, converting auth_id to username
            info_set = set( )
            for prop in info:
                if prop == 'auth_id':
                    info_set.add( 'username' )
                else:
                    info_set.add( prop )
            raise ConflictException( ':'.join( info_set ) )            
            
        return rm
            
    class LoginMessage( EndpointsModel ):
        # Request params
        username_or_email = ndb.StringProperty( )
        password = ndb.StringProperty( )

        # Response params
        user_id_auth_token = ndb.StringProperty( )
        user = ndb.StructuredProperty( User )

    @LoginMessage.method( request_fields=( 'username_or_email',
                                           'password', ),
                          response_fields=( 'user_id_auth_token', 'user', ),
                          path='login', http_method='POST', name='login' )
    def Login( self, lm ):
        # Check existence of request params
        if lm.username_or_email is None or lm.password is None:
            raise BadRequestException( 'No username, email or password '
                                       + 'given' )

        # Try to get the User
        auth_id = self.get_local_auth_id( lm.username_or_email )
        try:
            lm.user = User.get_by_auth_password( auth_id, lm.password )
        except InvalidAuthIdError:
            raise BadRequestException( 'Invalid credentials' )
        except InvalidPasswordError:
            raise BadRequestException( 'Invalid credentials' )
        user_id = lm.user.get_id( )
                
        # Log in user with auth token
        lm.user_id_auth_token = self.create_user_id_auth_token( user_id )
        if lm.user_id_auth_token is None:
            raise ConflictException(
                'Encountered conflict when creating auth token' )
        return lm

        
    class SocialLoginMessage( EndpointsModel ):
        # Request params
        access_token = ndb.StringProperty( )
        provider = ndb.StringProperty( )
        password = ndb.StringProperty( )

        # Response params
        user_id_auth_token = ndb.StringProperty( )
        user = ndb.StructuredProperty( User )
        password_required = ndb.BooleanProperty( default=False )

    @SocialLoginMessage.method( request_fields=( 'access_token', 'provider',
                                                 'password', ),
                                path='social_login',
                                http_method='POST',
                                name='social_login' )
    def SocialLogin( self, slm ):
        if slm.provider is None or slm.access_token is None:
            raise BadRequestException( 'No provider or access token given' )
        # Fetch the user info
        social_id = None
        url = PROVIDER_URLS.get( slm.provider.lower( ) )
        if url is None:
            raise BadRequestException( 'Unknown provider' )
        url = url.format( urlencode( { 'access_token': slm.access_token } ) )
        result = urlfetch.fetch( url )
        if result.status_code == 200:
            body = json.loads( result.content )
            social_id = body.get( 'id' )
            # Determine if email provided, if any, is verified
            if slm.provider.lower( ) == 'facebook':
                # Can assume Facebook emails are verified:
                # http://stackoverflow.com/questions/14280535
                # /is-it-possible-to-check-if-an-email-is-confirmed-on-facebook
                verified = True
            elif slm.provider.lower( ) == 'google':
                verified = body.get( 'verified_email' )
            else:
                logging.error( 'Unexpected provider: ' + slm.provider )
                raise BadRequestException( 'Unknown provider' )
            # Grab the social email and create a username based on the email
            # with most non-alphanumeric characters removed
            social_email = body.get( 'email' )
            username = None
            if social_email:
                username = social_email.split( '@' )[ 0 ]
                username = re.sub( '[^a-zA-Z0-9_-]+', '', username )
                if len( username ) > 17:
                    username = username[ :17 ]
            if not username:
                username = 'dummy'
            if not verified:
                # Don't actually use the social email if it is not verified
                social_email = None

        if social_id:
            # Need to fetch the user id associated with this social id
            # + email, or create a new user if one does not yet exist

            # Check if a user with this social id already exists
            auth_id = '{0}:{1}'.format( slm.provider.lower( ), social_id )
            slm.user = User.get_by_auth_id( auth_id )
            if slm.user is None:
                # Social id not in use. Try getting user by verified email
                # to see if we can add social login with an existing user
                if social_email is not None:
                    slm.user = User.get_by_email_verified( social_email )
                if slm.user is None:
                    # Email not in use either. Create a new user.

                    # Try creating a new user by varying the username
                    for num in range( 1000 ):
                        suffix = ''
                        if num > 0:
                            suffix = str( num )
                        this_username = username + suffix
                        unique_properties = [ 'username' ]
                        if social_email is not None:
                            unique_properties.append( 'email_verified' )
                            
                        ok, info = User.create_user(
                            auth_id,
                            unique_properties=unique_properties,
                            email_verified=social_email,
                            email_pending=social_email,
                            username=this_username,
                            is_mod=False )
                        if ok:
                            slm.user = info
                            break
                        elif( 'email' in info
                              and social_email is not None ):
                            # Looks like the social email is in use after all.
                            # This could happen, for instance, if a user tried
                            # to double register at the same time.
                            raise ConflictException(
                                'Email [' + social_email + '] for this account'
                                + ' is already in use. '
                                + 'Did you accidentally try to login twice, '
                                + 'or have you not verified your email address'
                                + ' yet?')
                    else:
                        # Failed to create an account after 1000 tries
                        raise ConflictException(
                            'Encountered conflict when creating new account.' )
                else:
                    # Email is in use, but social_id is not.
                    # If the User has a password, we require it before
                    # adding the social auth id to the User
                    if slm.user.has_password:
                        if not slm.password:
                            # Need a password, but none provided
                            slm.password_required = True
                            return slm
                        if not slm.user.check_password( slm.password ):
                            # Need a password, but provided password invalid
                            raise UnauthorizedException(
                                'Invalid credentials' )

                    # Now add the social auth id
                    ok, info = slm.user.add_auth_id( auth_id )
                    if ok:
                        slm.user = info
                    else:
                        raise ConflictException(
                            'Encountered conflict when adding auth id to '
                            + 'existing account, conflicting properties: '
                            + str( info ) )

            if( social_email
                and slm.user.email_pending_lower == social_email.lower( )
                and slm.user.email_verified_lower != social_email.lower( ) ):
                # Email is now verified by social login
                slm.user = self.validate_email_internal( slm.user )
                
            # Create auth token
            slm.user_id_auth_token = self.create_user_id_auth_token(
                slm.user.get_id( ) )
            if slm.user_id_auth_token is None:
                raise ConflictException(
                    'Encountered conflict when creating auth token' )
        else:
            raise BadRequestException(
                'Access token did not provide valid id' )

        return slm

    @endpoints.method( message_types.VoidMessage, message_types.VoidMessage,
                       path='logout', http_method='POST', name='logout' )
    def Logout( self, *args ):
        user_id, auth_token = self.get_current_user_id( )
        if not user_id:
            raise UnauthorizedException( 'Failed to get current user' )

        User.delete_auth_token( user_id, auth_token )
        return message_types.VoidMessage( )


    class SendEmailVerificationMessage( EndpointsModel ):
        # Request params
        username = ndb.StringProperty( )
        verification_url = ndb.StringProperty( )

        # Response params
        email = ndb.StringProperty( )

    @SendEmailVerificationMessage.method(
        request_fields=( 'username', 'verification_url', ),
        response_fields=( 'email', ),
        path='send_email_verification',
        http_method='POST',
        name='send_email_verification' )
    def SendEmailVerification( self, sevm ):
        user = self.protected_get_user_by_username( sevm.username )
        if user is None:
            raise UnauthorizedException( "Cannot send email verification for"
                                         + " other user!" )

        if not sevm.verification_url:
            raise BadRequestException( "No verification url provided!" )

        # Send email verification
        if not user.send_email_verification( sevm.verification_url ):
            raise ConflictException( 'Too many verificaiton emails sent.' )
        sevm.email = user.email_pending
        return sevm

        
    class VerifyEmailMessage( EndpointsModel ):
        token = ndb.StringProperty( )

    @VerifyEmailMessage.method( path='verify_email', http_method='POST',
                                name='verify_email' )
    def VerifyEmail( self, vem ):
        # We require users to be logged in to verify email
        user = self.get_current_user( verified_email_required=False )
        if user is None:
            raise UnauthorizedException( 'Must be logged in to verify email' )
        
        # Check for valid token
        user_id = user.get_id( )
        valid = User.validate_verify_email_token( user_id, vem.token )
        if not valid:
            raise BadRequestException( 'Invalid token for verifying email' )
        self.validate_email_internal( user )
        User.delete_verify_email_token( user_id, vem.token )
        return vem

        
    class PasswordResetMessage( EndpointsModel ):
        email = ndb.StringProperty( )
        set_password_url = ndb.StringProperty( )

    @PasswordResetMessage.method( path='password_reset', http_method='POST',
                                  name='password_reset' )
    def PasswordReset( self, prm ):
        user = User.get_by_email( prm.email )
        if user is None:
            raise BadRequestException( "No user registered with that email" )

        if not prm.set_password_url:
            raise BadRequestException( "No set password url provided" )

        # Send password reset email
        ok, msg = user.send_password_reset_email( prm.set_password_url )
        if not ok:
            raise ConflictException( msg )
        return prm


    class SetPasswordMessage( EndpointsModel ):
        new_password = ndb.StringProperty( )
        user_id = ndb.IntegerProperty( )
        token = ndb.StringProperty( )

    @SetPasswordMessage.method( path='set_password', http_method='POST',
                                name='set_password' )
    def SetPassword( self, spm ):
        # Check for valid new password
        ok, msg = self.valid_password( spm.new_password )
        if not ok:
            raise BadRequestException( msg )
        
        # Check for valid token + grab the user
        valid = User.validate_password_reset_token( spm.user_id, spm.token )
        if not valid:
            raise UnauthorizedException( 'Invalid token for setting password' )
        user = User.get_by_id( spm.user_id )

        # Set password
        ok, info = self.update_user_internal( user, user.email_pending,
                                              user.username,
                                              spm.new_password )
        if ok:
            # Password set successfully
            User.delete_password_reset_token( spm.user_id, spm.token )
        else:
            raise BadRequestException( 'An unknown error occurred. Please try'
                                       + ' again later.' )

        return spm
