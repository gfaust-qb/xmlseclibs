<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlsecEncryptNoreplaceTest extends PHPUnit_Framework_TestCase {

    /**
     * Encryption without modifying original data
     */
    public function test()
    {
        //$this->markTestSkipped('must be revisited.');
        $this->assertFileExists(__DIR__ . '/basic-doc.xml', "__DIR__/basic-doc.xml");

        $dom = new DOMDocument();
        $dom->load(__DIR__ . '/basic-doc.xml');

        $origData = $dom->saveXML();

        $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $objKey->generateSessionKey();

        $this->assertFileExists(__DIR__ . '/mycert.pem', "__DIR__/mycert.pem");

        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
        $siteKey->loadKey(__DIR__ . '/mycert.pem', TRUE, TRUE);

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($siteKey, $objKey);

        $enc->type = XMLSecEnc::Element;
        $encNode = $enc->encryptNode($objKey, FALSE);

        $newData = $dom->saveXML();

        $this->assertEquals($origData, $newData, 'Not Modified');

        $error = false;
        if ($encNode->namespaceURI !== XMLSecEnc::XMLENCNS || $encNode->localName !== 'EncryptedData') {
            //echo "Encrypted node wasn't a <xenc:EncryptedData>-element.\n";
            $error = true;
        }

        $this->assertFalse($error, 'Node');

    }
}
 