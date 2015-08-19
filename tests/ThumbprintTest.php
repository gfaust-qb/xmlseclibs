<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;

require_once(__DIR__ . '/../xmlseclibs.php');

class ThumbprintTest extends PHPUnit_Framework_TestCase {

    /**
     * Certificate thumbprint check
     */
    public function test()
    {
        $expectedThumbprint              = '8b600d9155e8e8dfa3c10998f736be086e83ef3b';
        $expectedThumbprintBase64Encoded = 'OGI2MDBkOTE1NWU4ZThkZmEzYzEwOTk4ZjczNmJlMDg2ZTgzZWYzYg==';
        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
        $siteKey->loadKey(__DIR__ . '/mycert.pem', TRUE, TRUE);

        $thumbprint = $siteKey->getX509Thumbprint();
        $this->assertEquals($expectedThumbprint , $thumbprint, 'Thumbprint');
        $this->assertEquals($expectedThumbprintBase64Encoded, base64_encode($thumbprint), 'Thumbprint Base64 encoded.');
    }

}
 