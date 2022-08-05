// cd php/src && php AccessToken.php
<?php
include "../src/AccessToken.php";

date_default_timezone_set("UTC");
$date = new DateTime();

$appID = "123456781234567812345678";
$appKey = "app key";
$roomID = "new room";
$userID = "new user id";

$token = AccessToken::init($appID, $appKey, $roomID, $userID);

$token->expireTime(0);
$token->addPrivilege($Privileges["PrivSubscribeStream"], 0);
$token->addPrivilege($Privileges["PrivPublishStream"], $date->getTimestamp() + 3600);

$s = $token->serialize();

var_dump($s);


$t = AccessToken::parse($s);

var_dump($t);

var_dump($t->verify($appKey));
?>