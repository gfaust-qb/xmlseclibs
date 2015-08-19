<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;
use DOMNode;
use Exception;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlsecDecryptTest extends PHPUnit_Framework_TestCase {

    /**
     * Basic Decryption
     */
    public function test()
    {

        $arTests = array('AOESP_SHA1'=>'oaep_sha1-res.xml');

        $doc = new DOMDocument();

        foreach ($arTests AS $testName=>$testFile) {
            $output = NULL;

            $doc->load(__DIR__ . "/$testFile");

            try {
                $objenc = new XMLSecEnc();
                $encData = $objenc->locateEncryptedData($doc);

                $this->assertNotNull($encData);

                $objenc->setNode($encData);
                $objenc->type = $encData->getAttribute("Type");
                $objKey = $objKey = $objenc->locateKey();

                $this->assertNotNull($objKey, 'We know the secret key, but not the algorithm');

                $key = NULL;

                if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
                    if ($objKeyInfo->isEncrypted) {
                        $objencKey = $objKeyInfo->encryptedCtx;
                        $this->locateLocalKey($objKeyInfo);
                        $key = $objencKey->decryptKey($objKeyInfo);
                    }
                }

                if (! $objKey->key && empty($key)) {
                    $this->locateLocalKey($objKey);
                }
                if (empty($objKey->key)) {
                    $objKey->loadKey($key);
                }

                $token = NULL;

                if ($decrypt = $objenc->decryptNode($objKey, TRUE)) {
                    $output = NULL;
                    if ($decrypt instanceof DOMNode) {
                        if ($decrypt instanceof DOMDocument) {
                            $output = $decrypt->saveXML();
                        } else {
                            $output = $decrypt->ownerDocument->saveXML();
                        }
                    } else {
                        $output = $decrypt;
                    }
                }
            } catch (Exception $e) {

            }

            $outfile = __DIR__ . "/basic-doc.xml";
            $res = NULL;

            $this->assertFileExists($outfile);

            if (file_exists($outfile)) {
                $resDoc = new DOMDocument();
                $resDoc->load($outfile);
                $res = $resDoc->saveXML();

                $this->assertNotNull($output);
                $this->assertEquals($output, $res, 'Decrypt: ' . $testName);

            }

        }

        //--EXPECTF--
        //AOESP_SHA1: Passed

    }

    /**
     * When we need to locate our own key based on something like a key name
     */
    private function locateLocalKey($objKey) {
        /* In this example the key is identified by filename */
        $filename = $objKey->name;
        if (! empty($filename)) {
            $objKey->loadKey(__DIR__ . "/$filename", TRUE);
        } else {
            $objKey->loadKey(__DIR__ . "/privkey.pem", TRUE);
        }
    }
}

