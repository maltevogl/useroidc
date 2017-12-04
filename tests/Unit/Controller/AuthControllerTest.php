<?php

namespace OCA\UserOidc\Tests\Unit\Controller;

use PHPUnit\Framework\TestCase;

use OCP\AppFramework\Http\TemplateResponse;

use OCA\UserOidc\Controller\AuthController;


class AuthControllerTest extends TestCase {
	private $controller;
	private $userId = 'john';

	public function setUp() {
		$request = $this->getMockBuilder('OCP\IRequest')->getMock();
		$config = $this->getMockBuilder('OCP\IConfig')->getMock();
		$logger = $this->getMockBuilder('OCP\ILogger')->getMock();
		$urlgenerator = $this->getMockBuilder('OCP\IURLGenerator')->getMock();
		$usermanager = $this->getMockBuilder('OCP\IUserManager')->getMock();
		$securerandom = $this->getMockBuilder('OCP\Security\ISecureRandom')->getMock();
		$session = $this->getMockBuilder('OC\Session\Memory')->disableOriginalConstructor()->getMock();
		$usersession = $this->getMockBuilder('OC\User\Session')->disableOriginalConstructor()->getMock();
    $usersession->method('getSession')->willReturn($session);
    $oidc = $this->getMockBuilder('OCA\UserOidc\UserOidcClient')->setConstructorArgs([$config])->getMock();

    $config->setSystemValue('openid_connect', ['provider' => [
			'displayName' => 'github',
      'provider' => 'https://example.com',
      'client_id' => '1234',
      'client_secret' => 'abcd',
			]]);

		$this->controller = new AuthController(
			'useroidc', $request,  $config, $logger, $urlgenerator, $usermanager,  $securerandom, $usersession, $session, $oidc
		);
	}

	public function testLogin() {
        $result = $this->controller->login("provider");
        $this->assertEquals('/', $result->getRedirectURL());
	}

}
