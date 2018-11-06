<?php

namespace OCA\UserOidc;

use OCP\IConfig;
use Jumbojett\OpenIDConnectClient;


/**
 * From jumbojett/OpenIDConnectClient
 * A wrapper around base64_decode which decodes Base64URL-encoded data,
 * which is not the same alphabet as base64.
 */
function decodeClaim($base64url) {
    return base64_decode(b64url2b64($base64url));
}
/**
 * Per RFC4648, "base64 encoding with URL-safe and filename-safe
 * alphabet".  This just replaces characters 62 and 63.  None of the
 * reference implementations seem to restore the padding if necessary,
 * but we'll do it anyway.
 *
 */
function b64url2b64($base64url) {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
	$base64url .= str_repeat("=", 4 - $padding);
    }
    return strtr($base64url, '-_', '+/');
}

class UserOidcClient {

    private $config, $oidc, $provider;

    public function __construct(IConfig $config) {
        $this->config = $config;
        $this->oidc = NULL;
        $this->provider = NULL;
    }

    public function setProvider($provider) {
        $this->provider = $provider;
        $oidc_config = $this->config->getSystemValue('openid_connect')[$provider];
        $oidc = new OpenIDConnectClient($oidc_config['provider'], $oidc_config['client_id'], $oidc_config['client_secret']);
        $this->oidc = $oidc;
    }

    public function cleanString($string) {
        return preg_replace('/[\x00-\x1F\x7F]/u', ' ', decodeClaim($string));
    }

    public function addScope($scope) {
        $this->oidc->addScope($scope);
    }

    public function setRedirectUrl($url) {
        $this->oidc->setRedirectUrl($url);
    }

    public function requestUserInfo($info) {
        return $this->oidc->requestUserInfo($info);
    }

    public function authenticate() {
        $this->oidc->authenticate();
    }

    public function getAccessToken() {
        return $this->oidc->getAccessToken();
    }

    public function getIdToken() {
        $claims = $this->oidc->getVerifiedClaims();
        $arrClaims = (array)$claims;
        return $arrClaims;
    }

    public function getSubClaim() {
        $sub = $this->oidc->getVerifiedClaims('sub');
        return $this -> cleanString($sub);
    }

    public function getNameClaim() {
        $name = $this -> getIdToken()['name'];
        return $name;
    }

    public function getEmailClaim() {
        $email = $this -> getIdToken()['email'];
        return $email;
    }
}
