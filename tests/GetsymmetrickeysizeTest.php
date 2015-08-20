<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;

require_once(__DIR__ . '/../xmlseclibs.php');

class GetsymmetrickeysizeTest extends PHPUnit_Framework_TestCase {

    /**
     * @group hhvm
     * Test getSymmetricKeySize().
     */
    public function test()
    {
        $keysizes = array(
            XMLSecurityKey::TRIPLEDES_CBC => 24,
            XMLSecurityKey::AES128_CBC => 16,
            XMLSecurityKey::AES192_CBC => 24,
            XMLSecurityKey::AES256_CBC => 32,
        );

        foreach ($keysizes as $type => $keysize) {
            $key = new XMLSecurityKey($type);
            $size = $key->getSymmetricKeySize();
            $this->assertEquals($keysize, $size, 'Keysize');
            if ($size !== $keysize) {
                printf("Invalid keysize for key type %s. Was %d, should have been %d.", $type, $size, $keysize);
                exit(1);
            }
        }

    }

}
 