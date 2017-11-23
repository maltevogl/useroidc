<?php
/**
 * ownCloud - useroidc
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Sigmund Augdal <sigmund.augdal@uninett.no>
 * @copyright Sigmund Augdal 2016
 */

namespace OCA\UserOidc\Controller;

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
use OCA\UserOidc\OpenIDConnectClient;


class AuthController extends Controller {

	function preg_whspc($string) {
	    return preg_replace('/\s+/', '', $string);
	}

	private $userId;

	public function __construct($AppName, IRequest $request, IConfig $config, ILogger $logger, IURLGenerator $urlgenerator, IUserManager $usermanager, ISecureRandom $securerandom, IUserSession $usersession, ISession $session, OpenIDConnectClient $oidc){
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

				$this->session['oidc_access_token'] = $this->oidc->getAccessToken();
				$this->log->debug('Got access token:' . $this->session['oidc_access_token'],['app' => $this->appName]);
				$this->session['oidc_id_token'] = $this->oidc->getIdToken();
				$this->log->debug('Got id token:' . $this->session['oidc_id_token'],['app' => $this->appName]);

				$this->session['oidc_sub_claim'] = $this->session['oidc_id_token']['sub'];
				$this->log->debug('Got sub claim:' . $this->session['oidc_sub_claim'],['app' => $this->appName]);
				$sub_array = explode('  ',trim($this->session['oidc_sub_claim']));
        $user_sub = reset($sub_array);
        $connector = end($sub_array);
				$this->log->debug('Got user from sub:' . $user_sub,['app' => $this->appName]);
				$this->log->debug('Got connector from sub:' . $connector,['app' => $this->appName]);

				if (strcmp($connector, 'github') == 0 or strcmp($connector, 'saml') == 0) {
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
					$this->log->debug('Got sub from unknown connector. Login not allowed.',['app' => $this->appName]);
					return new RedirectResponse('/');
				}

        $user = $this->usermanager->get($user_id);

        if(!$user) {
            $this->log->debug(implode(' ',array('Got unknown user:',$user_id,'from connector',$connector)),['app' => $this->appName]);
						$whitelist = file('apps/useroidc/whitelist.txt',FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
						$this->log->debug('Whitelist: '. implode(',',$whitelist),['app' => $this->appName]);
						if( in_array($user_id,$whitelist) )
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
            return $user;
        }
    }


}
