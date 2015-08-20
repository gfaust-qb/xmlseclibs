<?php
namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;
use DOMDocument;
use DOMElement;

require_once __DIR__ . '/../xmlseclibs.php';

/**
 * Class GeneratesessionkeyBasicsTest
 *
 * Basic tests for generateSessionKey().
 *
 * @package RobRichards\XMLSecLibs
 */
class GeneratesessionkeyBasicsTest extends PHPUnit_Framework_TestCase {

    /**
     * @group hhvm
     */
    public function test()
    {
        $key = new XMLSecurityKey(XMLSecurityKey::TRIPLEDES_CBC);
        $k = $key->generateSessionKey();
        $this->assertEquals($k, $key->key, 'Key');
        if ($key->key !== $k) {
            echo "Return value does not match generated key.";
            exit(1);
        }

        $keysizes = array(
            XMLSecurityKey::TRIPLEDES_CBC => 24,
            XMLSecurityKey::AES128_CBC => 16,
            XMLSecurityKey::AES192_CBC => 24,
            XMLSecurityKey::AES256_CBC => 32,
        );

        foreach ($keysizes as $type => $keysize) {
            $key = new XMLSecurityKey($type);
            $k = $key->generateSessionKey();
            $this->assertEquals($keysize, strlen($k), 'Keysize');
            if (strlen($k) !== $keysize) {
                printf("Invalid keysize for key type %s. Was %d, should have been %d.", $type, strlen($k), $keysize);
                exit(1);
            }
        }

        $this->assertTrue(true);

    }
}
 