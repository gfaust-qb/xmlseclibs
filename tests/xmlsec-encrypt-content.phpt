--TEST--
Basic Encryption: Content
--FILE--
<?php
require(__DIR__ . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

if (file_exists(__DIR__ . '/oaep_sha1.xml')) {
    unlink(__DIR__ . '/oaep_sha1.xml');
}

$dom = new DOMDocument();
$dom->load(__DIR__ . '/basic-doc.xml');

$objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$objKey->generateSessionKey();

$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
$siteKey->loadKey(__DIR__ . '/mycert.pem', TRUE, TRUE);

$enc = new XMLSecEnc();
$enc->setNode($dom->documentElement);
$enc->encryptKey($siteKey, $objKey);

$enc->type = XMLSecEnc::Content;
$encNode = $enc->encryptNode($objKey);

$dom->save(__DIR__ . '/oaep_sha1.xml');

$root = $dom->documentElement;
echo $root->localName."\n";

unlink(__DIR__ . '/oaep_sha1.xml');

?>
--EXPECTF--
Root
