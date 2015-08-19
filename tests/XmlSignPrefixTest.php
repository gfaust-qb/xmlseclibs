<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;

require_once(__DIR__ . '/../xmlseclibs.php');

class XmlSignPrefixTest extends PHPUnit_Framework_TestCase {

    /**
     * Basic Signature with no namespace prefix
     */
    public function test()
    {
        $prefixes = array('ds' => 'ds', 'pfx' => 'pfx', 'none' => null);

        foreach ($prefixes as $file_out => $prefix) {
            $doc = new DOMDocument();
            $doc->load(__DIR__ . '/basic-doc.xml');

            $objDSig = new XMLSecurityDSig($prefix);

            $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

            $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

            $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
            /* load private key */
            $objKey->loadKey(__DIR__ . '/privkey.pem', TRUE);

            /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */

            $objDSig->sign($objKey);

            /* Add associated public key */
            $options = array('issuerSerial' => true, 'subjectName' => true, );
            $objDSig->add509Cert(file_get_contents(__DIR__ . '/mycert.pem'), true, false, $options);

            $objDSig->appendSignature($doc->documentElement);
            $sig_out = "/xml-sign-prefix-$file_out.xml";
            $doc->save(__DIR__ . $sig_out);

            $this->assertXmlFileEqualsXmlFile(__DIR__ . "/xml-sign-prefix-$file_out.res", __DIR__ . $sig_out, 'Signed Output');
            //unlink(__DIR__ . $sig_out);
        }
    }
}
 