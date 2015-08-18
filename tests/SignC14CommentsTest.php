<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use PHPUnit_Framework_TestCase;

require_once __DIR__ . '/../xmlseclibs.php';

class SignC14CommentsTest extends PHPUnit_Framework_TestCase
{
    /**
     * C14N_COMMENTS signatures.
     * @description Test signing with C14N with comments.
     * @throws XMLSecurityException
     */
    public function test()
    {
        if (file_exists(__DIR__ . '/sign-c14-comments.xml')) {
            unlink(__DIR__ . '/sign-c14-comments.xml');
        }

        $xml = "<ApplicationRequest xmlns=\"http://example.org/xmldata/\"><CustomerId>12345678</CustomerId><Command>GetUserInfo</Command><Timestamp>1317032524</Timestamp><Status>ALL</Status><Environment>DEVELOPMENT</Environment><SoftwareId>ExampleApp 0.1\b</SoftwareId><FileType>ABCDEFG</FileType></ApplicationRequest>";

        $doc = new DOMDocument();
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;
        $doc->loadXML($xml);

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N_COMMENTS);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::C14N_COMMENTS));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
        /* load private key */
        $objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

        $objDSig->sign($objKey, $doc->documentElement);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);

        $doc->save(__DIR__ . '/sign-c14-comments.xml');

        $sign_output = file_get_contents(__DIR__ . '/sign-c14-comments.xml');
        $sign_output_def = file_get_contents(__DIR__ . '/sign-c14-comments.res');
        // We have to convert Lineendings and Encoding to be able to use an Assertion.
        $sign_output_def = utf8_encode(str_replace(array("\r\n", "\r"), "\n", $sign_output_def));
        $this->assertSame($sign_output_def, $sign_output, 'Sign Output');
        if ($sign_output != $sign_output_def) {
            echo "NOT THE SAME\n";
        }
        echo "DONE\n";

    }
}
