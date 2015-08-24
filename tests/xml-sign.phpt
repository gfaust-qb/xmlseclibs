--TEST--
Basic Signature
--FILE--
<?php
require(__DIR__ . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

if (file_exists(__DIR__ . '/sign-basic-test.xml')) {
    unlink(__DIR__ . '/sign-basic-test.xml');
}

$doc = new DOMDocument();
$doc->load(__DIR__ . '/basic-doc.xml');

$objDSig = new XMLSecurityDSig();

$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
/* load private key */
$objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

/* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


$objDSig->sign($objKey);

/* Add associated public key */
$objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'));

$objDSig->appendSignature($doc->documentElement);
$doc->save(__DIR__ . '/sign-basic-test.xml');

$sign_output = file_get_contents(__DIR__ . '/sign-basic-test.xml');
$sign_output_def = file_get_contents(__DIR__ . '/sign-basic-test.res');
if ($sign_output != $sign_output_def) {
	echo "NOT THE SAME\n";
}
echo "DONE\n";
?>
--EXPECTF--
DONE
