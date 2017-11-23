<?php
/**
 * nextcloud - useroidc
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Malte Vogl, based on work by Sigmund Augdal <sigmund.augdal@uninett.no>
 * @copyright Sigmund Augdal 2016
 */

namespace OCA\UserOidc\AppInfo;

use OCP\AppFramework\App;
use OC_App;

require_once __DIR__ . '/autoload.php';

class Application extends App {

  public function __construct () {
    parent::__construct('useroidc');
    $container = $this->getContainer();
    $urlGenerator = $container->query('OCP\IURLGenerator');
    $config = $container->query('ServerContainer')->getConfig();
    foreach ($config->getSystemValue('openid_connect') as $id => $data) {
        OC_APP::registerLogIn(array(
            'href' => $urlGenerator->linkToRoute('useroidc.auth.login', ['provider' => $id]),
            'name' => $data['displayName'],
        ));
    };
  }
}
/*
$app = new App('useroidc');
$container = $app->getContainer();

$urlGenerator = $container->query('OCP\IURLGenerator');
$config = $container->query('ServerContainer')->getConfig();
foreach ($config->getSystemValue('openid_connect') as $id => $data) {
    OC_APP::registerLogIn(array(
        'href' => $urlGenerator->linkToRoute('useroidc.auth.login', ['provider' => $id]),
        'name' => $data['displayName'],
    ));
}
*/
