<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlSignSha256RsaSha256Test extends PHPUnit_Framework_TestCase {

    /**
     * Signature RSA SHA256
     */
    public function test()
    {
        $this->markTestSkipped('must be revisited.');
        if (file_exists(__DIR__ . '/sign-sha256-rsa-sha256-test.xml')) {
            unlink(__DIR__ . '/sign-sha256-rsa-sha256-test.xml');
        }

        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA256, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));
        /* load private key */
        $objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

        /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);
        $doc->save(__DIR__ . '/sign-sha256-rsa-sha256-test.xml');

        $this->assertXmlFileEqualsXmlFile(__DIR__ . '/sign-sha256-rsa-sha256-test.res', __DIR__ . '/sign-sha256-rsa-sha256-test.xml', 'Signed Output');

    }
}
 