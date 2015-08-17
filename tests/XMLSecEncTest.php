<?php

namespace RobRichards\XMLSecLibs;

use PHPUnit_Framework_TestCase;

require_once __DIR__ . '/../xmlseclibs.php';


class XMLSecEncTest extends PHPUnit_Framework_TestCase
{
    public function testSetNode()
    {
        echo __DIR__;
        $xmlSecEnc = new XMLSecEnc();
        $domNodeGiven = new \DOMNode();
        $domNodeExpected = $domNodeGiven;
        $xmlSecEnc->setNode($domNodeGiven);
        $this->assertAttributeEquals($domNodeExpected, 'rawNode', $xmlSecEnc);
    }
}
