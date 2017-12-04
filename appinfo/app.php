<?php

namespace OCA\UserOidc\AppInfo;

use OCP\AppFramework\App;
use OC_App;

require_once __DIR__ . '/../vendor/autoload.php';

$app = new App('useroidc');
$container = $app->getContainer();
;
$urlGenerator = $container->query('OCP\IURLGenerator');
$config = $container->query('ServerContainer')->getConfig();

foreach ($config->getSystemValue('openid_connect') as $id => $data) {
    \OC_APP::registerLogIn(array(
        'href' => $urlGenerator->linkToRoute('useroidc.auth.login', ['provider' => $id]),
        'name' => $data['displayName'],
    ));
}
