<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use PHPUnit_Framework_TestCase;

require_once(__DIR__ . '/../xmlseclibs.php');


class GetcipherdataTest extends PHPUnit_Framework_TestCase {

    /**
     * Test the getCipherData() function.
     */
    public function test()
    {
        $dataCipherValueExpected = 'e3b188c5a139655d14d3f7a1e6477bc3';
        $keyCipherValueExpected  = 'b36f81645cb068dd59d69c7ff96e835a';

        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/oaep_sha1-res.xml');

        $objenc = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);
        $objenc->setNode($encData);

        $ciphervalue = $objenc->getCipherValue();
        $this->assertEquals($dataCipherValueExpected, md5($ciphervalue), 'Data CipherValue');

        $objKey = $objenc->locateKey();
        $objKeyInfo = $objenc->locateKeyInfo($objKey);
        $encryptedKey = $objKeyInfo->encryptedCtx;

        $keyCV = $encryptedKey->getCipherValue();
        $this->assertEquals($keyCipherValueExpected, md5($keyCV), "Key CipherValue");

    }
}
 