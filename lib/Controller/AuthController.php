<?php
namespace OCA\UserOidc\Controller;

use OC\Files\Filesystem;
use OCP\IRequest;
use OCP\IConfig;
use OCP\ILogger;
use OCP\ISession;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Controller;
use \OCP\IURLGenerator;
use \OCP\IUserManager;
use \OCP\IUserSession;
use \OCP\Security\ISecureRandom;
use OCP\AppFramework\Http\RedirectResponse;
use OCA\UserOidc\UserOidcClient;

class AuthController extends Controller {

	function preg_whspc($string) {
	    return preg_replace('/\s+/', '', $string);
	}

	public function __construct($AppName, IRequest $request, IConfig $config, ILogger $logger, IURLGenerator $urlgenerator, IUserManager $usermanager, ISecureRandom $securerandom, IUserSession $usersession, ISession $session, UserOidcClient $oidc){
		parent::__construct($AppName, $request);
		$this->config = $config;
		$this->log = $logger;
		$this->urlgenerator = $urlgenerator;
		$this->usermanager = $usermanager;
		$this->securerandom = $securerandom;
		$this->usersession = $usersession;
		$this->session = $session;
		$this->oidc = $oidc;
	}

	/**
	 * CAUTION: the @Stuff turns off security checks; for this page no admin is
	 *          required and no CSRF check. If you don't know what CSRF is, read
	 *          it up in the docs or you might create a security hole. This is
	 *          basically the only required method to add this exemption, don't
	 *          add it to any other method if you don't exactly know what it does
	 *
   * @PublicPage
   * @NoCSRFRequired
   * @UseSession
	 */
	 public function login($provider) {
	 		$this->oidc->setProvider($provider);
	 		$oidc_config = $this->config->getSystemValue('openid_connect')[$provider];
	 		$this->oidc->addScope($oidc_config['scopes']);
	 		$redirectUrl = $this->urlgenerator->linkToRouteAbsolute('useroidc.auth.login', ['provider' => $provider]);
	 		$this->log->debug('Using redirectUrl ' . $redirectUrl, ['app' => $this->appName]);
	 		$this->oidc->setRedirectUrl($redirectUrl);
	 		$this->oidc->authenticate();

	 		$this->session['oidc_sub_claim'] = $this->oidc->getSubClaim();
	 		$this->log->debug('Got sub claim:' . $this->session['oidc_sub_claim'],['app' => $this->appName]);
	 		$sub_array = explode('  ',trim($this->session['oidc_sub_claim']));
	 		$user_sub = reset($sub_array);
	 		$connector = end($sub_array);
	 		$this->log->debug('Got user from sub:' . $user_sub,['app' => $this->appName]);
	 		$this->log->debug('Got connector from sub:' . $connector,['app' => $this->appName]);


	 		if (strcmp($connector, 'github') == 0 or strcmp($connector, 'saml') == 0 or strcmp($connector, 'shibboleth') == 0) {
				$this->session['oidc_name_claim'] = $this->oidc->getNameClaim();
	 			$this->log->debug('Got name claim:' . $this->session['oidc_name_claim'],['app' => $this->appName]);
	 			$this->session['oidc_email_claim'] = $this->oidc->getEmailClaim();
	 			$this->log->debug('Got email claim:' . $this->session['oidc_email_claim'],['app' => $this->appName]);

	 			$name_nowhspc = strtolower($this->preg_whspc($this->session['oidc_name_claim']));

	 			$user_id = implode('_', array($name_nowhspc,$connector));
	 			$email = $this->session['oidc_email_claim'];
	 			$name = $this->session['oidc_name_claim'];
	 		} elseif (strcmp($connector, 'mitre') == 0) {
	 			$name_nowhspc = strtolower($this->preg_whspc($user_sub));

	 			$user_id = implode('_',array($name_nowhspc,$connector));
	 			$email = '';
	 			$name =  '';
	 		} else {
				$preferred_username = $this->oidc->requestUserInfo('preferred_username');
				// check if we got a username from keycloak
				if ($preferred_username != '') {
					$this->log->debug('Got sub from keycloak connector. Trying to use Keycloak',['app' => $this->appName]);
					$connector = 'keycloak';
					$this->session['oidc_name_claim'] = $this->oidc->getNameClaim();
					$this->session['oidc_email_claim'] = $this->oidc->getEmailClaim();
					$user_id = $this->oidc->requestUserInfo('preferred_username');
					$email = $this->session['oidc_email_claim'];
					$name = $this->session['oidc_name_claim'];
					$this->log->debug('Got userid:' . $user_id,['app' => $this->appName]);
					$this->log->debug('Got name claim:' . $name,['app' => $this->appName]);
					$this->log->debug('Got email claim:' .$email,['app' => $this->appName]);
				} else {
		 			$this->log->debug('Got sub from unknown connector. Login not allowed.',['app' => $this->appName]);
		 			return new RedirectResponse('/');
				}
	 		}

	 		$user = $this->usermanager->get($user_id);

	 		if(!$user) {
	 				$this->log->debug(implode(' ',array('Got unknown user:',$user_id,'from connector',$connector)),['app' => $this->appName]);
	 				$whitelist = file( __DIR__ . '/../../whitelist.txt',FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	 				$this->log->debug('Whitelist: '. implode(',',$whitelist),['app' => $this->appName]);
	 				if( in_array($connector,$whitelist) or  in_array($user_id,$whitelist) )
	 				{
	 					$this->log->debug($user_id.' is whitelisted. Will add to db.',['app' => $this->appName]);
	 					$user = $this->createUser($user_id, $name, $email);
	 					}
	 				else
	 				{
	 					$this->log->debug($user_id.' is not whitelisted, aborting.',['app' => $this->appName]);
	 					return new RedirectResponse('/');
	 					}
	 		}
	 		if(!$user) {
	 				return new RedirectResponse('/');
	 		}

	 		$this->doLogin($user, $user_id);
	 		return new RedirectResponse('/');

	 }

	 private function doLogin($user) {
	 		$this->usersession->getSession()->regenerateId();
	 		$this->usersession->createSessionToken($this->request, $user->getUID(), $user->getUID());
	 		if ($this->usersession->login($user->getUID(), $this->usersession->getSession()->getId())) {
	 				$this->log->debug('login successful', ['app' => $this->appName]);
	 				$this->usersession->createSessionToken($this->request, $user->getUID(), $user->getUID());
	 				if ($this->usersession->isLoggedIn()) {
	 				}
	 		}

	 }

	 private function createUser($uid, $name, $email) {
	 		if (preg_match( '/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
	 				$this->log->debug('Invalid username "'.$uid.'", allowed chars "a-zA-Z0-9" and "_.@-" ', ['app' => $this->appName]);
	 				return false;
	 		} else {
	 				$random_password = $this->securerandom->generate(64);
	 				$this->log->debug('Creating new user: '.$uid, ['app' => $this->appName]);
	 				$user = $this->usermanager->createUser($uid, $random_password);
	 				$user->setEMailAddress($email);
	 				$user->setDisplayName($name);
					$user->setEnabled(true);
					$user->setQuota('1GB');

					Filesystem::init($user->getUID(), '');
	 				return $user;
	 		}
	 }

}
