<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;
use Exception;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlsecVerifyRsaSha256Test extends PHPUnit_Framework_TestCase {

    /**
     * Verify RSA SHA256
     */
    public function test()
    {
        $doc = new DOMDocument();
        $arTests = array('SIGN_TEST_RSA_SHA256'=>'sign-sha256-rsa-sha256-test.xml');

        foreach ($arTests AS $testName=>$testFile) {
            $doc->load(__DIR__ . "/$testFile");
            $objXMLSecDSig = new XMLSecurityDSig();

            $objDSig = $objXMLSecDSig->locateSignature($doc);

            $this->assertNotNull($objDSig, 'Signature Node.');

            $objXMLSecDSig->canonicalizeSignedInfo();
            $objXMLSecDSig->idKeys = array('wsu:Id');
            $objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

            $retVal = $objXMLSecDSig->validateReference();

            $this->assertTrue($retVal, "Reference Validation.");

            $objKey = $objXMLSecDSig->locateKey();

            $this->assertNotNull($objKey, 'Find Key.');

            $key = NULL;

            $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

            if (! $objKeyInfo->key && empty($key)) {
                $objKey->loadKey(__DIR__ . '/mycert.pem', TRUE);
            }

            $this->assertEquals(1, $objXMLSecDSig->verify($objKey), 'Verify Signature.');
        }
        #--EXPECTF--
        #SIGN_TEST_RSA_SHA256: Signature validated!

    }
}
 