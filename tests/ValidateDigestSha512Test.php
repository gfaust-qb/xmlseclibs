<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use DOMXPath;
use PHPUnit_Framework_TestCase;

require_once(__DIR__ . '/../xmlseclibs.php');

class ValidateDigestSha512Test extends PHPUnit_Framework_TestCase {

    /**
     * Validate Digest SHA 512
     *
     * @group hhvm
     */
    public function test()
    {
        $doc = new DOMDocument();
        $doc->load(__DIR__ . '/basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA512, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
        /* load private key */
        $objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);

        $signed = $doc->saveXML();

        /* Validate the digest which we first split at char 64 to new line */
        $dom = new DOMDocument();
        $dom->loadXML($signed);
        /* Add linefeed after char 64 in the digest value */
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('dsig', XMLSecurityDSig::XMLDSIGNS);
        $query = '//dsig:DigestValue/text()';
        $nodeset = $xpath->query($query, $dom);

        $digestValue = $nodeset->item(0);
        $digestValue->insertData(63, "\n");

        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($dom);
        $this->assertNotNull($objDSig, 'Locate Signature');
        $this->assertInstanceOf('DOMNode', $objDSig, '$objDSig instanceof DOMNode');

        $objXMLSecDSig->canonicalizeSignedInfo();

        $retVal = false;
        try {
            $retVal = $objXMLSecDSig->validateReference();
        } catch (Exception $e) {}

        $this->assertTrue($retVal, 'Reference Validation Succeeded');
    }
}
 