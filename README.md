Authtopus
==========

Authtopus is a python authorization library for use with [Google Cloud Endpoints (GCE)](https://cloud.google.com/endpoints/).  While GCE does have authentication built-in, as of writing this document GCE authentication only supports registration / login using Google accounts.  Authtopus, on the other hand, supports standard username and password logins as well as logins via social accounts (only Facebook and Google currently supported, but more social providers could be supported in the future).  Registrations via different methods with matching verified email addresses are merged into one user account.

Check out the library in action in this very simple [Authtopus Example](https://authtopus.appspot.com) app.  If you think you might like to use this library in a new or existing project, then read on.  Note that I am by no means a web security expert and while I believe the library provides secure authentication, I cannot guarantee that I didn't miss something so the library is use at your own risk.

Installation
------------

1. The recommended method for obtaining Authtopus is to add the library as a submodule to an existing project.  For example, given that you already have a directory called `ext` that holds your third-party modules (or given that you have just created such a directory), you can then run:

`git submodule add https://github.com/rggibson/Authtopus.git ext/authtopus`

Adding the project as a submodule allows you to pull for new updates to the library when they become available.  Alternatively, you can simply copy the authtopus directory anywhere into your project and then copy a new, updated version when necessary.

Authtopus also depends on the [endpoints-proto-datastore](https://github.com/GoogleCloudPlatform/endpoints-proto-datastore) library.  This library must also be added to your project:

`git submodule add https://github.com/GoogleCloudPlatform/endpoints-proto-datastore.git ext/endpoints_proto_datastore`

2. Add the endpoints_proto_datastore and authtopus directories to your path by adding the following to appengine_config.py in your project's root directory (or create the file if it does not currently exist):

    import os
    import sys

    ENDPOINTS_PROJECT_DIR = os.path.join( os.path.dirname( __file__ ),
                                          'ext/endpoints_proto_datastore' )
    AUTHTOPUS_PROJECT_DIR = os.path.join( os.path.dirname( __file__ ),
                                          'ext/authtopus' )

    sys.path.extend( [ ENDPOINTS_PROJECT_DIR, AUTHTOPUS_PROJECT_DIR,
    		       # Other directories...
		     ] )

NOTE: I actually had trouble getting appengine_config.py to run properly on startup in the [Authtopus Example](https://authtopus.appspot.com) app.  If you are getting errors similar to "No module names authtopus.api" when trying to run your app, try putting this code in `main.py` before the code shown in step 3 below.

3. In `main.py` in your project's root directory, add the following lines if not already present:

    import endpoints
    import webapp2

    from authtopus.api import Auth
    from authtopus.cron import CleanupTokensHandler, CleanupUsersHandler

    API = endpoints.api_server( [ Auth,
    	  			  # Other APIs here...
				], restricted=False )

    CRON = webapp2.WSGIApplication(
    	 [ ( '/cron/auth/cleanup-token/?', CleanupTokensHandler ),
	   ( '/cron/auth/cleanup-users/?', CleanupUsersHandler ) ]
    )

4. In `app.yaml` add the following handlers and libraries if not already present:

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

And that's it!  Well, there's actually one more step required to get email verification and password reset emails working in production.  See the configuration section below for more details on that.

Usage
-----

Coming soon.

Configuration
-------------

Coming soon.

Contact
-------

 * Email: [richard.g.gibson@gmail.com](mailto:richard.g.gibson@gmail.com)
 * Twitter: [@RichardGGibson](https://twitter.com/richardggibson)
