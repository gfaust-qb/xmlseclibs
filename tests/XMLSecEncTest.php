<?php

namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;

require_once __DIR__ . '/src/xmlseclibs.php';


class XMLSecEncTest extends PHPUnit_Framework_TestCase
{
    public function testSetNode()
    {
        $xmlSecEnc = new XMLSecEnc();
        $domNodeGiven = new \DOMNode();
        $domNodeExpected = $domNodeGiven;
        $xmlSecEnc->setNode($domNodeGiven);
        $this->assertAttributeEquals($domNodeExpected, 'rawNode', $xmlSecEnc);
    }
}
