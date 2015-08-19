<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlSignSubjectTest extends PHPUnit_Framework_TestCase {

    /**
     * Basic Signature With Subject
     */
    public function test()
    {
        //$this->markTestSkipped('must be revisited.');
        $generatedFile = __DIR__ . '/sign-subject.xml';
        $expectedFile  = __DIR__ . '/sign-subject.res';

        if (file_exists($generatedFile)) {
            unlink($generatedFile);
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
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'), TRUE, FALSE, array('subjectName'=>TRUE));

        $objDSig->appendSignature($doc->documentElement);
        $doc->save($generatedFile);

        $this->assertXmlFileEqualsXmlFile($expectedFile, $generatedFile, 'Signed Output');
        //unlink($generatedFile);
    }
}
 