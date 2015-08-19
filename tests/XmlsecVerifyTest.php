<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlsecVerifyTest extends PHPUnit_Framework_TestCase {

    /**
     * Basic Verify
     */
    public function test()
    {
        $this->markTestSkipped('must be revisited.');
        $doc = new DOMDocument();
        $arTests = array('SIGN_TEST'=>'sign-basic-test.xml');

        foreach ($arTests AS $testName=>$testFile) {

            $this->assertFileExists(__DIR__ . "/$testFile", "__DIR__/$testFile");
            $doc->load(__DIR__ . "/$testFile");
            $objXMLSecDSig = new XMLSecurityDSig();

            $objDSig = $objXMLSecDSig->locateSignature($doc);

            $this->assertNotNull($objDSig, 'Locate Signature.');

            $objXMLSecDSig->canonicalizeSignedInfo();
            $objXMLSecDSig->idKeys = array('wsu:Id');
            $objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

            $retVal = $objXMLSecDSig->validateReference();

            $this->assertTrue($retVal, "Reference Validation.");

            $objKey = $objXMLSecDSig->locateKey();

            $this->assertNotNull($objKey, 'Key found.');

            $key = NULL;

            $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

            if (! $objKeyInfo->key && empty($key)) {

                $this->assertFileExists(__DIR__ . '/mycert.pem', "__DIR__/mycert.pem");

                $objKey->loadKey(__DIR__ . '/mycert.pem', TRUE);
            }

            $this->assertEquals(1, $objXMLSecDSig->verify($objKey), $testName . ': ' . 'Validate Signature.');

        }
    }
}
 