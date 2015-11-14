Authtopus
==========

Authtopus is a python authorization library for use with [Google Cloud Endpoints (GCE)](https://cloud.google.com/endpoints/).  While GCE does have authentication built-in, as of writing this document GCE authentication only supports registration / login using Google accounts.  Authtopus, on the other hand, supports standard username and password logins as well as logins via social accounts (only Facebook and Google currently supported, but more social providers could be supported in the future).  Registrations via different methods with matching verified email addresses are merged into one user account.

Check out the library in action in this very simple [Authtopus Example](https://authtopus.appspot.com) app.  If you think you might like to use this library in a new or existing project, then read on.  Note that I am by no means a web security expert and while I believe the library provides secure authentication, I cannot guarantee that I didn't miss something so the library is use at your own risk.

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

On the server side, new endpoints can retrieve the authentication user as follows:

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

  NOTE: I actually had trouble getting appengine_config.py to run properly on startup in the [Authtopus Example](https://authtopus.appspot.com) app.  If you are getting errors similar to "No module names authtopus.api" when trying to run your app, try putting this code in `main.py` before the code shown in step 3 below.

3. In `main.py` in your project's root directory, add the following lines if not already present (leaving out the optional cron handler if you choose to):

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
      # Optional cron handler that occasionally deletes inactive users with no verified email
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

And that's it!  Well, there's actually one more step required to get email verification and password reset emails working in production.  See the configuration section below for more details on that.

Endpoints
---------

- GET: `/auth/v1.0/current_user` - Retrieves the currently authenticated user
  Request fields:

  Response fields:
    * email_verified - The verified email of the user, if any
    * email_pending - The pending email of the user. May be same as email_verified.
    * username - The username of the user
    * has_password - Boolean indicating if the user can login via username and pasword (as opposed to only via social login)

  Errors:
    * 401 UnauthorizedException - Occurs if the authorization token provided is invalid.

- GET: `/auth/v1.0/get_user` - Retrieves a user by username
  Request fields:
    * username - The username of the user object we are requesting

  Response fields:
    * email_verified - The verified email of the user, if any
    * email_pending - The pending email of the user. May be same as email_verified.
    * username - The username of the user
    * has_password - Boolean indicating if the user can login via username and pasword (as opposed to only via social login)

  Errors:
    * 400 BadRequestException - Occurs if an invalid username is provided
    * 401 UnauthorizedException - Occurs if the requested username is not the username of the currently authenticated user and the currently authenticated user is not a mod (users can be assigned mod status in the datastore viewer of the developer's console)
    * 404 NoFoundException - Occurs if no user exists with the requested username

- POST: `/auth/v1.0/update_user` - Updates information for the user with the requested old_username
  Request fields:
    * old_username - The username of the user to update
    * email - The new email for the user
    * username - The new username for the user
    * old_password - The user's old password (empty to leave password unchanged)
    * password - The user's new password
    * verification_url - URL sent to the user's new email address where the user is directed to go to verify their new email address if necessary

  Response fields:
    * email - The new email for the user
    * username - The new username for the user

  Errors:
    * 400 BadRequestException - Occurs if any of the request parameters are invalid
    * 401 UnauthorizedException - Occurs if the requested old_username is not the username of the currently authenticated user and the currently authenticated user is not a mod
    * 409 ConflictException - Occurs if the new email or username are already in use by another User

- POST: `/auth/v1.0/register` - Registers a new user
  Request fields:
    

Retrieving Users on the Server
------------------------------

Coming soon.

Configuration
-------------

Coming soon.

Contact
-------

 * Email: [richard.g.gibson@gmail.com](mailto:richard.g.gibson@gmail.com)
 * Twitter: [@RichardGGibson](https://twitter.com/richardggibson)
