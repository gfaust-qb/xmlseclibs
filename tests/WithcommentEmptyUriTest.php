<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class WithcommentEmptyUriTest extends PHPUnit_Framework_TestCase {

    /**
     * WithComments with an ID reference.
     *
     * @description Checks that comments are removed when using an ID URI in a Reference.
     * @group hhvm
     */
    public function test()
    {
        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/withcomment-id-uri.xml');
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = array('xml:id');

        $objDSig = $objXMLSecDSig->locateSignature($doc);

        $this->assertNotNull($objDSig, 'Locate Signature');
        $this->assertInstanceOf('DOMNode', $objDSig, '$objDSig instanceof DOMNode');

        $retVal = $objXMLSecDSig->validateReference();
        /*
         * Since we are testing reference canonicalization, we don't need to
         * do more than reference validation here.
         */
        $this->assertTrue($retVal, 'Reference');
    }
}
 