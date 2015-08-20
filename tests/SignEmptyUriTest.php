<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use PHPUnit_Framework_TestCase;

require_once __DIR__ . '/../xmlseclibs.php';


class SignEmptyUriTest extends PHPUnit_Framework_TestCase
{
    /**
     * Signature Forcing Empty URI
     *
     * @group hhvm
     */
    public function test()
    {

        if (file_exists(__DIR__ . '/sign-empty-uri.xml')) {
            unlink(__DIR__ . '/sign-empty-uri.xml');
        }

        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'), array('force_uri' => true));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
        /* load private key */
        $objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

        /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);
        $doc->save(__DIR__ . '/sign-empty-uri.xml');

        $this->assertFileExists(__DIR__ . '/sign-empty-uri.xml', 'Target-File exists.');
        $this->assertXmlFileEqualsXmlFile(__DIR__ . '/sign-empty-uri.res', __DIR__ . '/sign-empty-uri.xml', 'XML-Files equals.');

        unlink(__DIR__ . '/sign-empty-uri.xml');

    }
}
