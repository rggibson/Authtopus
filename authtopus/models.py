import logging

from datetime import datetime, timedelta

from google.appengine.ext import ndb
from google.appengine.api import mail

from protorpc import messages

from webapp2_extras import security
from webapp2_extras.appengine.auth.models import UserToken as BaseUserToken
from webapp2_extras.appengine.auth.models import User as BaseUser

from endpoints_proto_datastore.ndb import EndpointsModel
from endpoints_proto_datastore.ndb.properties import EndpointsComputedProperty

from . import config

# The UserToken and User classes here are derived from the respective classes
# provided by webapp2_extras:
# https://webapp-improved.appspot.com/_modules/webapp2_extras/appengine/auth
# /models.html

class UserToken( BaseUserToken ):
    # Need the user to be indexed
    user = ndb.StringProperty( required=True, indexed=True )

    @classmethod
    def count( cls, user, subject, limit, life_hours ):
        """ Counts the number of valid tokens of type subject assigned to user.

        :param user:
            The id of the user in question
        :param subject:
            The subject of the key
        :param limit:
            Maximum number of tokens to count
        :returns:
            Integer counting the number of such tokens
        """
        q = cls.query( cls.user == str( user ), cls.subject == subject )
        tokens = q.order( -cls.created ).fetch( limit,
                                                projection=[ cls.created ] )
        res = 0
        for token in tokens:
            # Check if token is still valid
            if( token.created + timedelta( hours=life_hours )
                <= datetime.now( ) ):
                # Token has expired
                return res
            res += 1

        return res

# Special UserToken class for verify email tokens as they need to store an
# additional email property
class VerifyEmailUserToken( UserToken ):
    SUBJECT = 'verify_email'
    
    email = ndb.StringProperty( required=True )

    @classmethod
    def create( cls, user, email ):
        """ Creates a new verify email token for the given user for validating
            the given email.

        :param user:
            User unique ID
        :param email:
            Email that the token validates
        :returns:
            The newly created :class:`VerifyEmailUserToken`.
        """
        user = str( user )
        token = security.generate_random_string( entropy=128 )
        key = cls.get_key( user, cls.SUBJECT, token )
        entity = cls( key=key, user=user, subject=cls.SUBJECT, token=token,
                      email=email.lower( ) )
        entity.put( )
        return entity

    @classmethod
    def count_by_email( cls, user, email ):
        """ Counts the number of valid tokens of type subject assigned to user
            for the given email.

        :param user:
            The id of the user in question
        :param email:
            The given email
        :returns:
            Integer counting the number of such valid tokens
        """
        q = cls.query( cls.user == str( user ), cls.subject == cls.SUBJECT,
                       cls.email == email.lower( ) )
        tokens = q.order( -cls.created ).fetch(
            config.MAX_VERIFY_EMAIL_TOKENS_PER_EMAIL,
            projection=[ cls.created ] )
        res = 0
        for token in tokens:
            # Check if token is still valid
            if( token.created + timedelta(
                    hours=config.TOKEN_LIFE_HOURS.get( 'verify_email' ) )
                <= datetime.now( ) ):
                # Token has expired
                return res
            res += 1

        return res
    

def lower_or_none( s ):
    if s:
        return s.lower( )
    else:
        return None

class User( BaseUser, EndpointsModel ):
    _message_fields_schema = ( 'email_verified', 'email_pending', 'username',
                               'has_password' )
    token_model = UserToken
    
    # Additional User properties
    email_verified = ndb.StringProperty( default=None, indexed=False )
    email_verified_lower = ndb.ComputedProperty(
        lambda self: lower_or_none( self.email_verified ) )
    email_pending = ndb.StringProperty( default=None, indexed=False )
    email_pending_lower = ndb.ComputedProperty(
        lambda self: lower_or_none( self.email_pending ) )
    username = ndb.StringProperty( required=True, indexed=False )
    username_lower = ndb.ComputedProperty(
        lambda self: self.username.lower( ) )
    is_mod = ndb.BooleanProperty( default=False, indexed=False )
    has_password = EndpointsComputedProperty(
        lambda self: self.password is not None,
        property_type=messages.BooleanField,
        indexed=False )

    def check_password( self, password ):
        """ Checks that password is valid.
        :param password:
            The password to check
        :returns:
            True if password matches database, False otherwise
        """
        if password is not None and self.password is not None:
            return security.check_password_hash( password, self.password )
        else:
            return False

    def update( self, email, username, password ):
        """ Updates the User with new parameters.

        :param email:
            The new email_pending for the user
        :param username:
            The new username to assign to the user
        :param password:
            The new password to assign to the user
        :returns:
            A tuple (boolean, info) where on success, (True, user) is returned
            and on failure, (False, list) is returned where list gives names
            of the properties that conflict with existing unique properties.
        """
        # Set up unique properties
        uniques = [ ]
        if self.username_lower != username.lower( ):
            key = '%s.%s:%s' % ( self.__class__.__name__, 'username',
                                 username.lower( ) )
            uniques.append( ( key, 'username' ) )
        if( email
            and self.email_pending_lower != email.lower( )
            and self.email_verified_lower != email.lower( ) ):
            key = '%s.%s:%s' % ( self.__class__.__name__, 'email',
                                 email.lower( ) )
            uniques.append( ( key, 'email' ) )

        ok, existing = self.unique_model.create_multi( k for k, v in uniques )
        if ok:
            # No overlap with existing unique properties.
            # Remove the old unique values from the datastore.
            values = [ ]
            if self.username_lower != username.lower( ):
                key = '%s.%s:%s' % ( self.__class__.__name__, 'username',
                                     self.username_lower )
                values.append( key )
            if( self.email_pending
                and ( self.email_pending_lower != email.lower( ) )
                and ( self.email_pending_lower
                      != self.email_verified_lower ) ):
                key = '%s.%s:%s' % ( self.__class__.__name__, 'email',
                                     self.email_pending_lower )
                values.append( key )
            self.unique_model.delete_multi( values )

            # Update user
            self.username = username
            self.email_pending = email
            if password:
                self.password = security.generate_password_hash(
                    password, length=12 )
            self.put( )
            return True, self

        else:
            # Overlap with existing unique properties
            properties = [ v for k, v in uniques if k in existing ]
            return False, properties

    def cleanup_and_delete( self ):
        """ Deletes the user from the datastore along with all of the
            appropriate Unique entries

        :returns:
            None
        """
        # Set up unique properties to delete
        uniques = [ ]
        key = '%s.%s:%s' % ( self.__class__.__name__, 'username',
                             self.username_lower )
        uniques.append( key )
        if self.email_pending is not None:
            key = '%s.%s:%s' % ( self.__class__.__name__, 'email',
                                 self.email_pending_lower )
            uniques.append( key )
        if( self.email_verified is not None
            and self.email_verified_lower != self.email_pending_lower ):
            key = '%s.%s:%s' % ( self.__class__.__name__, 'email',
                                 self.email_verified_lower )
            uniques.append( key )
        for auth_id in self.auth_ids:
            key = '%s.%s:%s' % ( self.__class__.__name__, 'auth_id',
                                 auth_id )
            uniques.append( key )

        # Delete uniques then delete the user entity from the datastore
        self.unique_model.delete_multi( uniques )
        self.key.delete( )

    def send_email_verification( self, verification_url ):
        """ Sends a verificaiton email

        :param verification url:
            The URL the user must go to to verify their email
        :returns:
            True on success, False if too many verification emails have
            been sent
        """
        # Check for problems
        if not self.email_pending:
            logging.error( 'Unable to send email verification for user_id='
                           + str( self.get_id( ) ) + ' - no pending email' )
            return
        
        # Create a verify email token
        token = self.create_verify_email_token( self.get_id( ),
                                                self.email_pending )
        if token is None:
            return False

        # Send mail
        sender = config.EMAIL_SENDER
        to = self.email_pending
        subject = config.EMAIL_VERIFY_SUBJECT
        body = config.EMAIL_VERIFY_BODY.format( self.username, (
            verification_url + '?token=' + token ) )

        mail.send_mail( sender, to, subject, body )
        logging.debug( 'Mail body:\n' + body )

        return True

    def validate_email( self ):
        """ Updates the user's verified email to their pending email

        :returns:
            self
        """
        if self.email_verified_lower != self.email_pending_lower:
            if self.email_verified:
                # Remove the old unique email value
                values = [ '%s.%s:%s' % ( self.__class__.__name__, 'email',
                                          self.email_verified_lower ) ]
                self.unique_model.delete_multi( values )

            # Update user
            self.email_verified = self.email_pending
            self.put( )

        return self
        
    def send_password_reset_email( self, set_password_url ):
        """ Sends a password reset email

        :param set_password_url:
            The URL the user must go to to change their password
        :returns:
            ( True, None ) on success, ( False, msg ) on error
        """
        # Create password reset token
        token = self.create_password_reset_token( self.get_id( ) )
        if token is None:
            msg = ( "You currently have too many active password reset tokens."
                    + " You must wait for some tokens to expire before "
                    + "requesting a new token (tokens expire after "
                    + str( config.TOKEN_LIFE_HOURS.get( 'password_reset' ) )
                    + " hours)." )
            return False, msg
                    
        # Send mail
        sender = config.EMAIL_SENDER
        if self.email_verified:
            to = self.email_verified
        elif self.email_pending:
            to = self.email_pending
        else:
            return False, 'No email address found'
        subject = config.EMAIL_PASSWORD_RESET_SUBJECT
        body = config.EMAIL_PASSWORD_RESET_BODY.format( self.username, (
            set_password_url + '?user_id=' + str( self.get_id( ) )
            + '&token=' + token ) )

        mail.send_mail( sender, to, subject, body )
        logging.debug( 'Mail body:\n' + body )

        return True, None
        
    def remove_auth_id( self, auth_id ):
        """ Removes the given auth_id from the user.

        :param auth_id:
            The auth_id to remove.
        """
        if auth_id in self.auth_ids:
            self.auth_ids.remove( auth_id )
            unique = '%s.auth_id:%s' % ( self.__class__.__name__, auth_id )
            self.unique_model.delete_multi( [ unique ] )
            self.put( )

    # Class Methods
    @classmethod
    def get_by_username( cls, username ):
        """ Retrieves a User object by username

        :param username:
            Username of the User to retrieve
        :returns:
            The User corresponding to this username, or None if no such
            user exists.
        """
        if username:
            q = cls.query( cls.username_lower == username.lower( ) )
            return q.get( )
    
    @classmethod
    def get_by_email_verified( cls, email ):
        """ Retrieves a User object by verified email address

        :param email:
            Verified email address of the User to retrieve
        :returns:
            The User corresponding to this email, or None if no such
            user exists.
        """
        if email:
            q = cls.query( cls.email_verified_lower == email.lower( ) )
            return q.get( )

    @classmethod
    def get_by_email( cls, email ):
        """ Retrieves a User object by email address (verified or pending)

        :param email:
            Email address of the User to retrieve
        :returns:
            The User corresponding to this email, or None if no such
            user exists.
        """
        user = cls.get_by_email_verified( email )
        if user:
            return user
            
        if email:
            q = cls.query( cls.email_pending_lower == email.lower( ) )
            return q.get( )

    @classmethod
    def get_id_by_auth_id( cls, auth_id ):
        """Returns a user id based on an auth_id.

        :param auth_id:
            Unique auth id string for the user.
        :returns:
            A user id
        """
        key = cls.query( cls.auth_ids == auth_id ).get( keys_only=True )
        if key is not None:
            return key.id( )

    # We redefine the validate_token methods to account for lifespan of tokens
    @classmethod
    def validate_token( cls, user_id, subject, token, life_hours ):
        """ Checks for existence of an unexpired token, given user_id,
            subject, and token.

        :param user_id:
            Unique user id
        :param subject:
            The subject of the key
        :param token:
            The token string to be evaluated
        :param life_hours:
            Total number of hours the token is valid for
        :returns:
            True if token exists and is valid, False otherwise
        """
        t = cls.token_model.get( user=user_id, subject=subject, token=token )
        if t is not None:
            return t.created + timedelta( hours=life_hours ) > datetime.now( )
        else:
            return False

    @classmethod
    def validate_auth_token( cls, user_id, token ):
        return cls.validate_token( user_id, 'auth', token,
                                   config.TOKEN_LIFE_HOURS.get( 'auth' ) )

    # Signup tokens not currently used, but redefined here just in case
    # they are used in the future
    @classmethod
    def validate_signup_token( cls, user_id, token ):
        return cls.validate_token( user_id, 'signup', token, 0 )

    # Create, validate and delete verify email token follows those for
    # auth and signup tokens implemented in BaseUser class, with the
    # exception that our verify email tokens need to store the email
    # where the token was sent to. Otherwise, a malicious user could
    # send a verification email to a real address, then change to a fake
    # address, then follow the verify email link and end up verifying a fake
    # address.
    @classmethod
    def create_verify_email_token( cls, user_id, email ):
        """ Create a new verify email reset token

        :param user_id:
            The unique user_id of the user requesting the token.
        :param email:
            The email that the token will be sent to for verification.
        :returns:
            Token string that is created on success, or None if this user
            currently has too many valid verify email tokens for this
            email.
        """
        num_tokens = VerifyEmailUserToken.count_by_email( user_id, email )
        if num_tokens >= config.MAX_VERIFY_EMAIL_TOKENS_PER_EMAIL:
            # Too many tokens
            return None

        if not email:
            return None
        entity = VerifyEmailUserToken.create( user_id, email )
        return entity.token

    @classmethod
    def validate_verify_email_token( cls, user_id, token ):
        """ Checks for existence of an unexpired verify email token whose
            email matches the user's pending email

        :param user_id:
            Unique user id
        :param token:
            The token string to be evaluated
        :returns:
            True if token exists and is valid, False otherwise
        """
        t = VerifyEmailUserToken.get(
            user=user_id, subject=VerifyEmailUserToken.SUBJECT, token=token )
        if t is not None:
            if( t.created + timedelta(
                    hours=config.TOKEN_LIFE_HOURS.get( 'verify_email' ) )
                <= datetime.now( ) ):
                # Token expired
                return False
            # Check that token's email matches user's pending email
            user = ndb.model.Key( cls, user_id ).get( )
            return user and user.email_pending_lower == t.email.lower( )
        else:
            return False

    @classmethod
    def delete_verify_email_token( cls, user_id, token ):
        VerifyEmailUserToken.get_key( user_id, VerifyEmailUserToken.SUBJECT,
                                      token ).delete( )

    # Create, validate and delete password reset token follows those for
    # auth and signup tokens implemented in BaseUser class
    @classmethod
    def create_password_reset_token( cls, user_id ):
        """ Creates a new password reset token

        :param user_id:
            The unique user_id of the user requesting the token.
        :returns:
            Token string that is created on success, or None if this user
            currently has too many valid password reset tokens.
        """
        num_tokens = cls.token_model.count(
            user_id, 'password_reset', config.MAX_PASSWORD_RESET_TOKENS,
            config.TOKEN_LIFE_HOURS.get( 'password_reset' ) )
        if num_tokens >= config.MAX_PASSWORD_RESET_TOKENS:
            # Too many tokens for this user
            return None
            
        entity = cls.token_model.create( user_id, 'password_reset' )
        return entity.token

    @classmethod
    def validate_password_reset_token( cls, user_id, token ):
        return cls.validate_token(
            user_id, 'password_reset', token,
            config.TOKEN_LIFE_HOURS.get( 'password_reset' ) )

    @classmethod
    def delete_password_reset_token( cls, user_id, token ):
        cls.token_model.get_key( user_id, 'password_reset', token ).delete( )

    @classmethod
    def create_user( cls, auth_id, unique_properties=None, **user_values ):
        """Creates a new user.

        :param auth_id:
            A string that is unique to the user. Users may have multiple
            auth ids. Example auth ids:

            - own:username
            - own:email@example.com
            - google:username
            - yahoo:username

            The value of `auth_id` must be unique.
        :param unique_properties:
            Sequence of extra property names that must be unique up to
            case sensitivity.
        :param user_values:
            Keyword arguments to create a new user entity. Since the model is
            an ``Expando``, any provided custom properties will be saved.
            To hash a plain password, pass a keyword ``password_raw``.
        :returns:
            A tuple (boolean, info). The boolean indicates if the user
            was created. If creation succeeds, ``info`` is the user entity;
            otherwise it is a list of duplicated unique properties that
            caused creation to fail.
        """
        
        # One of the reasons we are overloading BaseUser.create_user here is
        # to ensure
        # that usernames and emails are converted to lower case before
        # checking for uniqueness.  BaseUser, on the other hand, considers
        # two values that differ only by case to be unique.  We don't want
        # this.  In addition, we store both pending and verified emails with
        # the same label 'email' in the Unique model.
        assert user_values.get( 'password' ) is None, \
            'Use password_raw instead of password to create new users.'

        assert not isinstance( auth_id, list ), \
            'Creating a user with multiple auth_ids is not allowed, ' \
            'please provide a single auth_id.'

        if 'password_raw' in user_values:
            user_values['password'] = security.generate_password_hash(
                user_values.pop( 'password_raw' ), length=12 )

        user_values['auth_ids'] = [ auth_id ]
        user = cls( **user_values )

        # Set up unique properties.
        uniques = [ ( '%s.auth_id:%s' % ( cls.__name__, auth_id ),
                      'auth_id' ) ]
        if unique_properties:
            for name in unique_properties:
                this_name = name
                if this_name.startswith( 'email' ):
                    this_name = 'email'
                key = '%s.%s:%s' % ( cls.__name__, this_name,
                                     user_values[ name ].lower( ) )
                uniques.append( ( key, this_name ) )

        ok, existing = cls.unique_model.create_multi( k for k, v in uniques )
        if ok:
            user.put( )
            return True, user
        else:
            properties = [ v for k, v in uniques if k in existing ]
            return False, properties
