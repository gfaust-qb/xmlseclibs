<?php

namespace RobRichards\XMLSecLibs;

use DOMDocument;
use Exception;

require_once(dirname(__FILE__) . '/../xmlseclibs.php');

/**
 * Extract Public Key
 */

class ExtractWinCertTest extends \PHPUnit_Framework_TestCase {

    public function testExtractWinCert() {
        $doc = new DOMDocument();
        $arTests = array(
            'SIGN_TEST'=>'sign-basic-test.xml',
            'ERROR_TEST'=>'sign-basic-test.xml'
        );

        foreach ($arTests AS $testName=>$testFile) {
            $doc->load(dirname(__FILE__) . "/$testFile");
            $objXMLSecDSig = new XMLSecurityDSig();

            $objDSig = $objXMLSecDSig->locateSignature($doc);

            $this->assertNotNull($objDSig, "Locate Signature Node");

            if (! $objDSig) {
                throw new Exception("Cannot locate Signature Node");
            }

            $objXMLSecDSig->canonicalizeSignedInfo();
            $objXMLSecDSig->idKeys = array('wsu:Id');
            $objXMLSecDSig->idNS = array('wsu'=>'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

            $retVal = $objXMLSecDSig->validateReference();

            $this->assertTrue($retVal,"Reference Validation");

            if (! $retVal) {
                throw new Exception("Reference Validation Failed");
            }

            $objKey = $objXMLSecDSig->locateKey();
            if ($testName == 'SIGN_TEST') {
                $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', TRUE);
                if ($objXMLSecDSig->verify($objKey)) {
                    $success = true;
                    $msg = "Signature validated!";
                } else {
                    $success = false;
                    $msg = "Failure!!!!!!!!";
                }
                $this->assertTrue($success, $msg);
            }
            if ($testName == 'ERROR_TEST') {
                try {
                    $objKey->loadKey(dirname(__FILE__) . '/mycert.win.pem', TRUE);
                    $success = true;
                    $msg = "PASS";
                } catch (Exception $e) {
                    $success = false;
                    $msg = $e->getMessage();
                }
                $this->assertFalse($success, $msg);
            }

        }

    }

}
 