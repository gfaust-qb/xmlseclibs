<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;
use DOMElement;

require_once __DIR__ . '/../xmlseclibs.php';

class EncrypteddataNodeOrderTest extends PHPUnit_Framework_TestCase {

    public function testBasicDoc() {

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

            $nodeOrder = array(
                'EncryptionMethod',
                'KeyInfo',
                'CipherData',
                'EncryptionProperties',
            );

            $prevNode = 0;
            for ($node = $encNode->firstChild; $node !== NULL; $node = $node->nextSibling) {
                if (! ($node instanceof DOMElement)) {
                    /* Skip comment and text nodes. */
                    continue;
                }

                $name = $node->localName;

                $cIndex = array_search($name, $nodeOrder, TRUE);
                $this->assertNotFalse($cIndex, "Unknown node: $name");

                if ($cIndex >= $prevNode) {
                    /* In correct order. */
                    $prevNode = $cIndex;
                    continue;
                }
                $prevName = $nodeOrder[$prevNode];
                $this->assertGreaterThanOrEqual($cIndex, $prevNode, "Incorrect order: $name must appear before $prevName");
            }

            $this->assertTrue(true, 'OK');
        }
}
 