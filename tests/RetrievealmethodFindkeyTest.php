<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use Exception;
use PHPUnit_Framework_TestCase;

require_once(dirname(__FILE__) . '/../xmlseclibs.php');

class RetrievealmethodFindkeyTest extends PHPUnit_Framework_TestCase
{

    /**
     * Test for ds:RetrievalMethod.
     *
     * @throws Exception
     */
    public function test()
    {

        $doc = new DOMDocument();
        $doc->load(__DIR__ . "/retrievalmethod-findkey.xml");

        $objenc = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);
        $this->assertNotNull($encData, 'Encrypted Data');
        if (! $encData) {
            throw new Exception("Cannot locate Encrypted Data");
        }
        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        $objKey = $objenc->locateKey();

        $objKeyInfo = $objenc->locateKeyInfo($objKey);

        $this->assertTrue($objKeyInfo->isEncrypted, '$objKeyInfo');
        if (!$objKeyInfo->isEncrypted) {
            throw new Exception('Expected $objKeyInfo to refer to an encrypted key by now.');
        }

    }
}
