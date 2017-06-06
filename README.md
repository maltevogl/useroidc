# User Oidc
Place this app in **owncloud/apps/**

Configure your openid connect providers in config.php like this:
```php
  'openid_connect' => [
    'dataporten' => [
      'displayName' => 'Dataporten',
      'provider' => 'https://auth.dataporten.no',
      'client_id' => 'XXXXXX',
      'client_secret' => 'XXXXXXX',
      'scopes' => array('openid','email','profile','groups'),
    ],
    'google' => [
      'displayName' => 'Google',
      'provider' => 'https://accounts.google.com',
      'client_id' => 'XXXXXX.apps.googleusercontent.com',
      'client_secret' => 'XXXXXX',
      'scopes' => array('openid','email','profile'),
    ]
  ],
```

If your owncloud install lives at https://oc.example.com/index.php and
the key for your provider in the config file is `google` you should
register `https://oc.example.com/index.php/apps/useroidc/login/google`
as redirect url at your provider.

If your want to add additional business logic, for instance limiting who can access this owncloud install you can create a new app and add a hook for the \OC\User postLogin hook. The access token associated with this login is available in the session at `oidc_access_token` at this point. Reject the login by calling `usersession::logout()` at this point.

## Building the app

The app can be built by using the provided Makefile by running:

    make

This requires the following things to be present:
* make
* which
* tar: for building the archive
* curl: used if phpunit and composer are not installed to fetch them from the web
* npm: for building and testing everything JS, only required if a package.json is placed inside the **js/** folder

The make command will install or update Composer dependencies if a composer.json is present and also **npm run build** if a package.json is present in the **js/** folder. The npm **build** script should use local paths for build systems and package managers, so people that simply want to build the app won't need to install npm libraries globally, e.g.:

**package.json**:
```json
"scripts": {
    "test": "node node_modules/gulp-cli/bin/gulp.js karma",
    "prebuild": "npm install && node_modules/bower/bin/bower install && node_modules/bower/bin/bower update",
    "build": "node node_modules/gulp-cli/bin/gulp.js"
}
```
## Testing travis

Updated


## Publish to App Store

First get an account for the [App Store](http://apps.owncloud.com/) then run:

    make appstore

The archive is located in build/artifacts/appstore and can then be uploaded to the App Store.

## Running tests
You can use the provided Makefile to run all tests by using:

    make test

This will run the PHP unit and integration tests and if a package.json is present in the **js/** folder will execute **npm run test**

Of course you can also install [PHPUnit](http://phpunit.de/getting-started.html) and use the configurations directly:

    phpunit -c phpunit.xml

or:

    phpunit -c phpunit.integration.xml

for integration tests
