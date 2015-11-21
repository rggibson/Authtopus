Authtopus
==========

Authtopus is a python authorization library for use with [Google Cloud Endpoints (GCE)](https://cloud.google.com/endpoints/).  While GCE does have authentication built-in, as of writing this document GCE authentication only supports registration / login using Google accounts.  Authtopus, on the other hand, supports standard username and password logins as well as logins via social accounts (only Facebook and Google currently supported, but more social providers could be supported in the future).  Registrations via different methods with matching verified email addresses are merged into one user account.

Check out the library in action in this very simple [Authtopus Example](https://authtopus.appspot.com) app, along with [the code that runs the app](https://github.com/rggibson/Authtopus-Example).  If you think you might like to use this library in a new or existing project, then read on.  Note that I am by no means a web security expert and while I believe the library provides secure authentication, I cannot guarantee that I didn't miss something so the library is use at your own risk.

Basic Usage
-----------

To demonstrate basic usage of Authtopus on the frontend, we provide code examples using AngulasJS's $http service.  A new user registers by submitting a POST request to the `/auth/v1.0/register` endpoint with their requested credentials:

```javascript
$http.post( 'https://<name_of_site>/_ah/api/auth/v1.0/register', {
  username: 'MrCool',
  password: 'iamCooL',
  email: 'mrcool@domain.com',
  verificiation_url: '<url_sent_to_users_email_address_to_verify_email>'
  } );
```

Upon successful registration, an email is sent to the provided email address asking the user to verify their email address by proceeding to the verification url provided in the POST request above.  In addition, after successful registration, the user can then login by sending a POST request to the `/auth/v1.0/login` endpoint with their credentials:

```javascript
$http.post( 'https://<name_of_site>/_ah/api/auth/v1.0/login', {
  username_or_email: 'MrCool',
  password: 'iamCooL'
  } );
```

Alternatively, a user can login using their Facebook or Google account by sending a POST request to the `/auth/v1.0/social_login` endpoint.  A new user will be registered automatically if this is their first time logging in:

```javascript
$http.post( 'https://<name_of_site>/_ah/api/auth/v1.0/social_login', {
  access_token: <access_token_from_social_provider>,
  provider: 'Facebook'
  } );
```

Upon successful login, the server responds with a `user_id_auth_token` string and a `user` object containing the user's username, email and information indicating if the email has been verified.  In order to authenticate future requests, the user must set the `Authorization` header to the received `user_id_auth_token` value.  For example, the user can request another verification email be sent by sending an authorized POST request to the `auth/v1.0/verify_email` endpoint:

```javascript
$http.defaults.headers.common['Authorization'] = <user_id_auth_token>;
$http.post( 'https://<name_of_site>/_ah/api/auth/v1.0/verify_email', {
  username: 'MrCool',
  verification_url: '<url_sent_to_users_email_address_to_verify_email>'
  } );
```

On the server side, new endpoints can retrieve the authenticated user as follows:

```python
from endpoints import UnauthorizedException
from authtopus.api import Auth

def myApiMethod( self, ... ):
    user = Auth.get_current_user( verified_email_required=True )
    if user is None:
        raise UnauthorizedException( 'Invalid credentials' )

    # user authentication successful, so continue with stuff...
```

Installation
------------

1. The recommended method for obtaining Authtopus is to add the library as a submodule to an existing project.  For example, given that you already have a directory called `ext` that holds your third-party modules (or given that you have just created such a directory), you can then run:

  `git submodule add https://github.com/rggibson/Authtopus.git ext/authtopus`

  Adding the project as a submodule allows you to pull for new updates to the library when they become available.  Alternatively, you can simply copy the authtopus directory anywhere into your project and then copy a new, updated version when necessary.

  Authtopus also depends on the [endpoints-proto-datastore](https://github.com/GoogleCloudPlatform/endpoints-proto-datastore) library.  This library must also be added to your project:
  
  `git submodule add https://github.com/GoogleCloudPlatform/endpoints-proto-datastore.git ext/endpoints_proto_datastore`

2. Add the endpoints_proto_datastore and authtopus directories to your path by adding the following to appengine_config.py in your project's root directory (or create the file if it does not currently exist):

  ```python

  import os
  import sys

  ENDPOINTS_PROJECT_DIR = os.path.join( os.path.dirname( __file__ ),
                                        'ext/endpoints_proto_datastore' )
  AUTHTOPUS_PROJECT_DIR = os.path.join( os.path.dirname( __file__ ),
                                        'ext/authtopus' )

  sys.path.extend( [ ENDPOINTS_PROJECT_DIR, AUTHTOPUS_PROJECT_DIR,
    				# Other directories if you have more...
		     		] )
  ```

  NOTE: I actually had trouble getting appengine_config.py to run properly on startup in the [Authtopus Example](https://github.com/rggibson/Authtopus-Example) app.  If you are getting errors similar to "No module names authtopus.api" when trying to run your app, try putting this code in `main.py` before the code shown in step 3 below.

3. In `main.py` in your project's root directory, add the following lines if not already present:

  ```python

  import endpoints
  import webapp2

  from authtopus.api import Auth
  from authtopus.cron import CleanupTokensHandler, CleanupUsersHandler

  API = endpoints.api_server( [ Auth,
    	  			# Other APIs here...
		], restricted=False )

  CRON = webapp2.WSGIApplication(
    [ ( '/cron/auth/cleanup-token/?', CleanupTokensHandler ),
      ( '/cron/auth/cleanup-users/?', CleanupUsersHandler ), ]
  )
  ```

4. In `app.yaml` add the following handlers and libraries if not already present:

  ```python

  handlers:
  - url: /_ah/spi/.*
    script: main.API
  - url: /cron/.*
    script: main.CRON
    login: admin

  libraries:
  - name: pycrypto
    version: latest
  - name: endpoints
    version: 1.0
  - name: webapp2
    version: 2.5.2
  ```
  
5. In `cron.yaml` add the following handlers (create the file in your project's main directory if it does not already exist).  You can skip the optional handler if you like:

  ```python
  
  cron:
  - description: clean up expired tokens
    url: /cron/auth/cleanup-tokens
    schedule: every 24 hours
  
  # Optional cron handler that occasionally deletes inactive users with no verified email  
  - description: clean up unverified, inactive users
    url: /cron/auth/cleanup-users
    schedule: every 168 hours
  ```
  
  Feel free to change the schedule to however often you like.
  

And that's it!  Well, there's actually one more step required to get email verification and password reset emails working in production.  See the configuration section below for more details on that.

Endpoints
---------

- GET: `/auth/v1.0/current_user` - Retrieves the currently authenticated user

  Request fields:

  Response fields:
    * `email_verified` - The verified email of the user, if any
    * `email_pending` - The pending email of the user. May be same as email_verified.
    * `username` - The username of the user
    * `has_password` - Boolean indicating if the user can login via username and password (as opposed to only via social login)

  Errors:
    * 401 `UnauthorizedException` - Occurs if the authorization token provided is invalid.

- GET: `/auth/v1.0/get_user` - Retrieves a user by username

  Request fields:
    * `username` - The username of the user object we are requesting

  Response fields:
    * `email_verified` - The verified email of the user, if any
    * `email_pending` - The pending email of the user. May be same as email_verified.
    * `username` - The username of the user
    * `has_password` - Boolean indicating if the user can login via username and pasword (as opposed to only via social login)

  Errors:
    * 400 `BadRequestException` - Occurs if an invalid username is provided
    * 401 `UnauthorizedException` - Occurs if the requested username is not the username of the currently authenticated user and the currently authenticated user is not a mod (users can be assigned mod status in the datastore viewer of the developer's console)
    * 404 `NotFoundException` - Occurs if no user exists with the requested username

- POST: `/auth/v1.0/update_user` - Updates information for the user with the requested `old_username`

  Request fields:
    * `old_username` - The username of the user to update
    * `email` - The new email for the user
    * `username` - The new username for the user
    * `old_password` - The user's old password (empty to leave password unchanged)
    * `password` - The user's new password
    * `verification_url` - URL sent to the user's new email address where the user is directed to go to verify their new email address if necessary

  Response fields:
    * `email` - The new email for the user
    * `username` - The new username for the user

  Errors:
    * 400 `BadRequestException` - Occurs if any of the request parameters are invalid.  The request parameters that are invalid are indicated in the error message, separated by '|' characters, where each part of the message is of the form `<field>:<invalid reason>`.
    * 401 `UnauthorizedException` - Occurs if the requested old_username is not the username of the currently authenticated user and the currently authenticated user is not a mod
    * 409 `ConflictException` - Occurs if the new email or username are already in use by another User.  The error message indicates which fields are conflicted, separated by a '|' character.

- POST: `/auth/v1.0/register` - Registers a new user

  Request and response fields:
    * `email` - The user's email
    * `username` - The user's username
    * `password` - The user's password
    * `verification_url` - URL sent to the user's email address where the user is directed to go to verify their email address

  Errors:
    * 400 `BadRequestException` - Occurs if any of the request parameters are invalid.  The request parameters that are invalid are indicated in the error message, separated by '|' characters, where each part of the message is of the form `<field>:<invalid reason>`.
    * 409 `ConflictException` - Occurs if the email or username are already in use by another User.  The error message indicates which fields are conflicted, separated by a '|' character.

- POST: `/auth/v1.0/login` - Logs a user in

  Request fields:
    * `username_or_email` - The username or email of the user logging in
    * `password` - The password of the user logging in

  Response fields:
    * `user_id_auth_token` - Token that should the `Authorization` header should be set to in order to authenticate all future requests.
    * `user` - User object for the logged in user containing the same fields as the response fields of `/auth/v1.0/current_user`.

  Errors:
    * 400 `BadRequestException` - Occurs if invalid credentials are provided
    * 409 `ConflictException` - Occurs in rare case when creating an authorization token fails.

- POST: `/auth/v1.0/social_login` - Logs a user in via a social provider, registering the user in the process if necessary

  Request and response fields:
    * `access_token` - Access token from the social provider
    * `provider` - The social provider.  Currently only 'Facebook' and 'Google' are supported.
    * `password` - The user's password, if any

  Response fields:
    * `user_id_auth_token` - Token that should the `Authorization` header should be set to in order to authenticate all future requests.
    * `user` - User object for the logged in user containing the same fields as the response fields of `/auth/v1.0/current_user`.
    * `password_required` - Boolean value indicating whether a password is required to complete the login.  When true, no `user_id_auth_token` or `user` will be provided in the response.  This field will only be true when a user has already registered with a verified email address that matches the verified email address from the social provider, and that user has a password for logging in.  In this case, the user should resend the request with the user's password.  This will merge the user's social id with their User account and future social logins will not require a password.

  Errors:
    * 400 `BadRequestException` - Occurs when a bad access token or provider is given
    * 401 `UnauthorizedException` - Occurs when attempting to merge a social login with a username and password login for the first time, but the provided password is invalid.
    * 409 `ConflictException` - Occurs when email is already in use by another user, but that user has not verified the email address.  Also occurs in other rare instances when authtopus fails to set a unique username for the User or fails to generate an authorization token.

- POST: `/auth/v1.0/logout` - Logs the currently logged in user out

  Request and response fields:

  Errors:
    * 401 `UnauthorizedException` - Occurs when no valid authorization token is provided

- POST: `/auth/v1.0/send_email_verification` - Sends a new email requesting verification of the user's email address

  Request fields:
    * `username` - The username of the user to send the email to
    * `verification_url` - URL sent to the user's email address where the user is directed to go to verify their email address.  A `token` parameter will be appended to this URL .

  Response fields:
    * `email` - The email address that the verification email was sent to

  Errors:
    * 400 `BadRequestException` - Occurs when no verification url is provided
    * 401 `UnauthorizedException` - Occurs when the requested `username` does not belong to the currently authorized user and the currently authenticated user is not a mod
    * 409 `ConflictException` - Occurs when too many verification emails have recently been sent to the user's email address (see Configuration section below)

- POST: `/auth/v1.0/verify_email` - Verify a user's email address

  Request and response fields:
    * `token` - Verification token that was appended to the `verification_url` when sent

  Erros:
    * 400 `BadRequestException` - Occurs when token is invalid
    * 401 `UnauthorizedException` - Occurs when either no user is authenticated or the currently authenticated user does not own the requested token

- POST: `/auth/v1.0/password_reset` - Sends a password reset email

  Request and response fields:
    * `email` - The email to send the password reset information to
    * `set_password_url` - URL that the user is directed to proceed to in order to reset their password.  A `user_id` and `token` are appended as parameters to the URL that the user requires to set a new password.

  Errors:
    * 400 `BadRequestException` - Occurs when no user currently registered with the provided email or no `set_password_url` is provided
    * 409 `ConflictException` - Occurs when sending email fails

 - POST: `/auth/v1.0/set_password` - Sets a new password for the user

   Request and response fields:
     * `new_password` - The new password for the user
     * `user_id` - The id of the user requesting a new password
     * `token` - Password reset token from the password reset email

   Errors:
     * 400 `BadRequestException` - Occurs when `password` does not meet the required criteria (4-20 characters in length)
     * 401 `UnauthorizedException` - Occurs when an invalid token is provided

Retrieving Users on the Server
------------------------------

There are two ways to retrieve users from the server in python. The first is described above in the Basic Usage section by using the `Auth.get_current_user` function.  The second way is to retrieve a specifc user by username:

```python
from endpoints import UnauthorizedException
from authtopus.api import Auth

def myApiMethod( self, ... ):
    username = # ...
    
    user = Auth.protected_get_user_by_username( username )
    if user is None:
        # Occurs when the current authenticated user's username is not
        # username and the current authenticated user is not a mod
        raise UnauthorizedException( 'Invalid credentials' )

    # Retrieved user successfully. Do stuff...
```

Configuration
-------------

There are a few configuration options available in `authtopus/config.py`.  Firstly, you can edit the email sender, subject, and body of emails that are sent for both email verification and password resets.  Note that for email to work in production, `config.EMAIL_SENDER` must be set to a valid sender address according to [the GAE mail documentation](https://cloud.google.com/appengine/docs/python/mail/#Python_Sending_mail).  Emails are also logged at the DEBUG level, so you can see emails in your log when running the development server with the `--log_level debug` option.

Secondly, the lifespan of various tokens can be set by modifying the values in `config.TOKEN_LIFE_HOURS`.  Note that auth tokens should have a short lifespan so that if the token happens to be compromised, an attacker will only have access for a short period of time.

Finally, there are also limits to how many unexpired password reset and verify email tokens a user can have, as well as the maximum number of tokens and user to potentially delete each time the respective cron job runs.  When employing the cron job to delete inactive users with no verified email, the amount of inactivity time can be set by the `config.UNVERIFIED_USER_LIFE_HOURS` parameter.

Contact
-------

 * Email: [richard.g.gibson@gmail.com](mailto:richard.g.gibson@gmail.com)
 * Twitter: [@RichardGGibson](https://twitter.com/richardggibson)
