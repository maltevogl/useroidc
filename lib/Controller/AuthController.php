<?php

namespace OCA\UserOidc\Controller;

use OC\Files\Filesystem;
use OCA\UserOidc\UserOidcClient;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\ISecureRandom;

class AuthController extends Controller
{

    function preg_whspc($string)
    {
        return preg_replace('/\s+/', '', $string);
    }

    public function __construct($AppName, IRequest $request, IConfig $config, ILogger $logger, IURLGenerator $urlgenerator, IUserManager $usermanager, IGroupManager $groupmanager, ISecureRandom $securerandom, IUserSession $usersession, ISession $session,ITimeFactory $timeFactory, UserOidcClient $oidc)
    {
        parent::__construct($AppName, $request);
        $this->config = $config;
        $this->log = $logger;
        $this->urlgenerator = $urlgenerator;
        $this->usermanager = $usermanager;
        $this->groupmanager = $groupmanager;
        $this->securerandom = $securerandom;
        $this->usersession = $usersession;
        $this->timeFactory = $timeFactory;
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
    public function login($provider)
    {
        $this->oidc->setProvider($provider);
        $oidc_config = $this->config->getSystemValue('openid_connect')[$provider];
        $this->oidc->addScope($oidc_config['scopes']);
        $redirectUrl = $this->urlgenerator->linkToRouteAbsolute('useroidc.auth.login', ['provider' => $provider]);
        $this->log->debug('Using redirectUrl ' . $redirectUrl, ['app' => $this->appName]);
        $this->oidc->setRedirectUrl($redirectUrl);
        $this->oidc->authenticate();

        $this->session['oidc_sub_claim'] = $this->oidc->getSubClaim();
        $this->log->debug('Got sub claim:' . $this->session['oidc_sub_claim'], ['app' => $this->appName]);
        $sub_array = explode('  ', trim($this->session['oidc_sub_claim']));
        $user_sub = reset($sub_array);
        $connector = end($sub_array);
        $this->log->debug('Got user from sub:' . $user_sub, ['app' => $this->appName]);
        $this->log->debug('Got connector from sub:' . $connector, ['app' => $this->appName]);


        if (strcmp($connector, 'github') == 0 or strcmp($connector, 'saml') == 0 or strcmp($connector, 'shibboleth') == 0) {
            $this->session['oidc_name_claim'] = $this->oidc->getNameClaim();
            $this->log->debug('Got name claim:' . $this->session['oidc_name_claim'], ['app' => $this->appName]);
            $this->session['oidc_email_claim'] = $this->oidc->getEmailClaim();
            $this->log->debug('Got email claim:' . $this->session['oidc_email_claim'], ['app' => $this->appName]);

            $name_nowhspc = strtolower($this->preg_whspc($this->session['oidc_name_claim']));

            $user_id = implode('_', array($name_nowhspc, $connector));
            $email = $this->session['oidc_email_claim'];
            $name = $this->session['oidc_name_claim'];
        } elseif (strcmp($connector, 'mitre') == 0) {
            $name_nowhspc = strtolower($this->preg_whspc($user_sub));

            $user_id = implode('_', array($name_nowhspc, $connector));
            $email = '';
            $name = '';
        } else {
            $preferred_username = $this->oidc->requestUserInfo('preferred_username');
            // check if we got a username from keycloak
            if ($preferred_username != '') {
                $this->log->debug('Got sub from keycloak connector. Trying to use Keycloak', ['app' => $this->appName]);
                $connector = 'keycloak';
                $this->session['oidc_name_claim'] = $this->oidc->getNameClaim();
                $this->session['oidc_email_claim'] = $this->oidc->getEmailClaim();
                $user_id = $this->oidc->requestUserInfo('preferred_username');
                $email = $this->session['oidc_email_claim'];
                $name = $this->session['oidc_name_claim'];
                $this->log->debug('Got userid:' . $user_id, ['app' => $this->appName]);
                $this->log->debug('Got name claim:' . $name, ['app' => $this->appName]);
                $this->log->debug('Got email claim:' . $email, ['app' => $this->appName]);
            } else {
                $this->log->debug('Got sub from unknown connector. Login not allowed.', ['app' => $this->appName]);
                return new RedirectResponse('/');
            }
        }

        $user = $this->usermanager->get($user_id);

        if (!$user) {
            $this->log->debug(implode(' ', array('Got unknown user:', $user_id, 'from connector', $connector)), ['app' => $this->appName]);
            if ($user_id) {
                $this->log->debug($user_id . ' is valid. Will add to db.', ['app' => $this->appName]);
                $user = $this->createUser($user_id, $name, $email);
            } else {
                $this->log->debug($user_id . ' is not valid, aborting.', ['app' => $this->appName]);
                return new RedirectResponse('/');
            }
        }
        if (!$user) {
            return new RedirectResponse('/');
        } else {
            $roles = $this->oidc->requestUserInfo('roles');
            $this->log->debug('Got roles:' . $roles, ['app' => $this->appName]);
            foreach ((array)$roles as $role) {
                $group = $this->groupmanager->get($role);
                if (!$group) {
                    $this->groupmanager->createGroup($role);
                    $group = $this->groupmanager->get($role);
                    $this->log->debug('Creating non-existing group:' . $role, ['app' => $this->appName]);
                }
                if ($group->inGroup($user)) {
                    $this->log->debug('User already in group:' . $role, ['app' => $this->appName]);
                } else {
                    $this->log->debug('Adding user to group:' . $role, ['app' => $this->appName]);
                    $group->addUser($user);
                }
            }
        }
        $this->doLogin($user, $user_id);
        return new RedirectResponse('/');

    }

    private function doLogin($user)
    {
        $this->usersession->getSession()->regenerateId();
        $this->usersession->createSessionToken($this->request, $user->getUID(), $user->getUID());
        if ($this->usersession->login($user->getUID(), $this->usersession->getSession()->getId())) {
            $this->log->debug('login successful', ['app' => $this->appName]);
            $this->usersession->createSessionToken($this->request, $user->getUID(), $user->getUID());
            if ($this->usersession->isLoggedIn()) {
                $now = $this->timeFactory->getTime();
                $this->session->set('last-password-confirm', $now);
                $user->updateLastLoginTimestamp();
            }
        }

    }

    private function createUser($uid, $name, $email)
    {
        if (preg_match('/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
            $this->log->debug('Invalid username "' . $uid . '", allowed chars "a-zA-Z0-9" and "_.@-" ', ['app' => $this->appName]);
            return false;
        } else {
            $random_password = $this->securerandom->generate(64);
            $this->log->debug('Creating new user: ' . $uid, ['app' => $this->appName]);
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