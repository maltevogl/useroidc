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

use PHPUnit\Framework\TestCase;

use OCP\AppFramework\Http\TemplateResponse;


class AuthControllerTest extends TestCase {

	private $controller;
	private $userId = 'john';

	public function setUp() {
		$request = $this->getMockBuilder('OCP\IRequest')->getMock();
		$config = $this->getMockBuilder('OCP\IConfig')->getMock();
		$logger = $this->getMockBuilder('OCP\ILogger')->getMock();
		$urlgenerator = $this->getMockBuilder('OCP\IURLGenerator')->getMock();
		$usermanager = $this->getMockBuilder('OCP\IUserManager')->getMock();
        $user = $this->getMockBuilder('OCP\IUser')->getMock();
        $usermanager->method('createUser')->willReturn($user);
		$securerandom = $this->getMockBuilder('OCP\Security\ISecureRandom')->getMock();
		$session = $this->getMockBuilder('OC\Session\Memory')->disableOriginalConstructor()->getMock();
		$usersession = $this->getMockBuilder('OC\User\Session')->disableOriginalConstructor()->getMock();
        $usersession->method('getSession')->willReturn($session);
        //$oidc = $this->getMockBuilder('OCA\UserOidc\OpenIDConnectClient')->setConstructorArgs([$config])->getMock();
        $oidc = $this->getMock('OCA\UserOidc\OpenIDConnectClient');//->setConstructorArgs([$config])->getMock();
        $oidc->setConstructorArgs([$config]);

	    print_r($oidc);

        $config->setSystemValue('openid_connect', ['provider' => [
            'displayName' => 'Test Provider',
            'provider' => 'https://example.com',
            'client_id' => '1234',
            'client_secret' => 'abcd',
        ]]);

		$this->controller = new AuthController(
			'useroidc', $request, $config, $logger, $urlgenerator, $usermanager, $securerandom, $usersession, $session, $oidc
		);
	}


	public function testLogin() {
        $result = $this->controller->login("provider");
        $this->assertEquals('/', $result->getRedirectURL());
	}

}
