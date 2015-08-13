<?php
namespace RobRichards\XMLSecLibs;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2015, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author    Robert Richards <rrichards@cdatazone.org>
 * @copyright 2007-2015 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityStrategyFactory implements XMLSecurityStrategy {

    /** @var XMLSecurityStrategyBase */
    private $strategy = null;

    /**
     * @param $type
     * @param XMLSecurityParams $params
     */
    public function __construct($type, XMLSecurityParams $xmlSecurityParams)
    {
        switch((string)$type) {
            case 'mcrypt':
                $this->strategy = new XMLSecurityStrategyMcrypt($xmlSecurityParams);
                break;
            case 'openssl':
                $this->strategy = new XMLSecurityStrategyOpenssl($xmlSecurityParams);
                break;
            default:
                throw new XMLSecException('Unsupported strategy: ' . print_r($type,true));
        }
    }

    /**
     * @param string $data
     * @return mixed
     */
    public function encryptData($data)
    {
        return $this->strategy->encryptData($data);
    }

    /**
     * @param string $data
     * @return mixed
     */
    public function decryptData($data)
    {
        return $this->strategy->decryptData($data);
    }

    /**
     * @return string
     */
    public function generateSessionKey()
    {
        return $this->strategy->generateSessionKey();
    }

    /**
     * @param string $data
     * @param string $signature
     * @return int
     */
    public function verifySignature($data, $signature)
    {
        return $this->strategy->verifySignature($data, $signature);
    }

    /**
     * @param string $data
     * @return mixed
     */
    public function signData($data)
    {
        return $this->strategy->signData($data);
    }
}
 