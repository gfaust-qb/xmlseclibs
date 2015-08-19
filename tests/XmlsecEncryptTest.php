<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlsecEncryptTest extends PHPUnit_Framework_TestCase {

    /**
     * Basic Encryption
     */
    public function test()
    {
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

        $enc->type = XMLSecEnc::Element;
        $encNode = $enc->encryptNode($objKey);

        $dom->save(__DIR__ . '/oaep_sha1.xml');

        $root = $dom->documentElement;

        $this->assertEquals('EncryptedData', $root->localName);

        //unlink(__DIR__ . '/oaep_sha1.xml');

        #--EXPECTF--
        #EncryptedData

    }
}
 