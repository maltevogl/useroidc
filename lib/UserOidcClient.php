<?php

namespace OCA\UserOidc;

use OCP\IConfig;
use Jumbojett\OpenIDConnectClient;

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

    public function decodeClaim($string) {
        $this->oidc->base64url_decode($string);
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
        return $this->oidc->getIdTokenPayload();
    }

    public function getSubClaim() {
        $sub = $this->oidc->getVerifiedClaims('sub');
        return cleanString($sub);
    }

    public function getNameClaim() {
        $name =  $this->oidc->getVerifiedClaims('name');
        return cleanString($name);
    }

    public function getEmailClaim() {
        $email = $this->oidc->getVerifiedClaims('email');
        return cleanString($email);

    }
}
