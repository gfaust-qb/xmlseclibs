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

class XMLSecurityStrategyFactory {

    /** @var XMLSecurityStrategyBase */
    private $strategy = null;

    /**
     * @param XMLSecurityParams $xmlSecurityParams
     * @throws XMLSecException
     */
    public function __construct(XMLSecurityParams $xmlSecurityParams)
    {
        switch ($xmlSecurityParams->getLibrary()) {
            case XMLSecurityKey::PHP_EXTENSION_MCRYPT:
                $this->strategy = new XMLSecurityStrategyMcrypt($xmlSecurityParams);
                break;
            case XMLSecurityKey::PHP_EXTENSION_OPENSSL:
                $this->strategy = new XMLSecurityStrategyOpenssl($xmlSecurityParams);
                break;
            case XMLSecurityKey::HMAC_SHA1:
                $this->strategy = new XMLSecurityStrategyHmac($xmlSecurityParams);
                break;
            default:
                throw new XMLSecException('Unsupported strategy: ' . print_r($xmlSecurityParams->getLibrary(), true));
        }

        return $this;
    }

    /**
     * @return XMLSecurityStrategy
     */
    public function get()
    {
        return $this->strategy;
    }

}
 