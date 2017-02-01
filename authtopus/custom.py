import logging

# This function is called after a new user is created. Put any custom code
# that you would like performed after a user is created here.  For example,
# you could create a profile with additional user-related properties that is
# linked to this user's id
def user_created( user, data ):
    """ Custom user created code here.
    :param user:
        The user that was just created.
    :returns:
        None
    """
    logging.info( '''User created with id={i}, username={u}
    with extra data={d}'''.format( i=user.key.id( ), u=user.username,
                                   d=data ) )
