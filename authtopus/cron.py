import logging

from datetime import datetime, timedelta

from webapp2 import RequestHandler

from .config import TOKEN_LIFE_HOURS, TOKEN_DELETE_LIMIT
from .config import UNVERIFIED_USER_DELETE_LIMIT, UNVERIFIED_USER_LIFE_HOURS
from .models import UserToken, VerifyEmailUserToken, User
from .api import Auth

class CleanupTokensHandler( RequestHandler ):
    def get( self ):
        """ Removes all tokens that have expired. When the last email
            verification token has been removed for a user, their
            email_pending is reset to their email_verified.
        """
        for subject in TOKEN_LIFE_HOURS.keys( ):
            # Run through all the tokens, ordered by creation time, deleting
            # until we find a token that has not expired yet
            if subject == 'verify_email':
                # Handle verify email separately in order to check for emails
                # with no more tokens at the end of the delete process
                q = VerifyEmailUserToken.query( ).order(
                    VerifyEmailUserToken.created )
                tokens = q.fetch( TOKEN_DELETE_LIMIT,
                                  projection=[ VerifyEmailUserToken.created,
                                               VerifyEmailUserToken.user,
                                               VerifyEmailUserToken.email ] )

                # Delete expired tokens
                info_deleted = set( )
                for token in tokens:
                    # Check if token has expired
                    if( token.created + timedelta(
                            hours=TOKEN_LIFE_HOURS.get( subject ) )
                        <= datetime.now( ) ):
                        logging.debug( 'Deleting token ['
                                       + str( token.key.id( ) ) + ']' )
                        info_deleted.add( ( token.user, token.email ) )
                        token.key.delete( )
                    else:
                        logging.debug( 'Token [' + str( token.key.id( ) )
                                       + '] still valid' )
                        break

                # Modify pending emails with no valid verification tokens
                for ( user_id, email ) in info_deleted:
                    if( VerifyEmailUserToken.count_by_email( user_id,
                                                             email ) <= 0 ):
                        # Reset pending email to verified email
                        user = User.get_by_id( int( user_id ) )
                        if user is None:
                            logging.error( 'No user found with id ['
                                           + str( user_id ) + ']' )
                        elif( user.email_pending_lower == email.lower( )
                            and user.email_verified ):
                            Auth.update_user_internal( user,
                                                       user.email_verified,
                                                       user.username )
                
            else:
                q = UserToken.query( UserToken.subject == subject )
                tokens = q.order( UserToken.created ).fetch(
                    TOKEN_DELETE_LIMIT, projection=[ UserToken.created ] )
                for token in tokens:
                    # Check if token has expired
                    if( token.created + timedelta(
                            hours=TOKEN_LIFE_HOURS.get( subject ) )
                        <= datetime.now( ) ):
                        logging.debug( 'Deleting token ['
                                       + str( token.key.id( ) ) + ']' )
                        token.key.delete( )
                    else:
                        logging.debug( 'Token [' + str( token.key.id( ) )
                                       + '] still valid' )
                        break

class CleanupUsersHandler( RequestHandler ):
    def get( self ):
        """ Deletes users that have no verified email address and have not
            been updated recently
        """
        q = User.query( User.email_verified_lower == None )
        users = q.order( User.updated ).fetch( UNVERIFIED_USER_DELETE_LIMIT )
        for user in users:
            if( user.updated + timedelta(
                    hours=UNVERIFIED_USER_LIFE_HOURS ) <= datetime.now( ) ):
                logging.debug( 'Deleting user [' + str( user.key.id() ) + ']' )
                user.cleanup_and_delete( )
            else:
                logging.debug( 'User [' + str( user.key.id() )
                               + '] still good' )
                break
