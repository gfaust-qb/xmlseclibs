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

class XMLSecurityParams
{

    /** @var string */
    private $certificateType = '';

    /** @var string */
    private $library = '';

    /** @var string */
    private $mode = '';

    /** @var string */
    private $method = '';

    /** @var string */
    private $digest = '';

    /** @var string */
    private $padding = '';

    /** @var string */
    private $cipher = '';

    /** @var int */
    private $keysize = 0;

    /** @var string */
    private $hash = '';

    /**
     * @return string
     */
    public function getCertificateType()
    {
        return $this->certificateType;
    }

    /**
     * @param string $certificateType
     * @return XMLSecurityParams
     */
    public function setCertificateType($certificateType)
    {
        $this->certificateType = $certificateType;
        return $this;
    }

    /**
     * @return string
     */
    public function getLibrary()
    {
        return $this->library;
    }

    /**
     * @param string $library
     * @return XMLSecurityParams
     */
    public function setLibrary($library)
    {
        $this->library = $library;
        return $this;
    }

    /**
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * @param string $mode
     * @return XMLSecurityParams
     */
    public function setMode($mode)
    {
        $this->mode = $mode;
        return $this;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * @param string $method
     * @return XMLSecurityParams
     */
    public function setMethod($method)
    {
        $this->method = $method;
        return $this;
    }

    /**
     * @return string
     */
    public function getDigest()
    {
        return $this->digest;
    }

    /**
     * @param string $digest
     * @return XMLSecurityParams
     */
    public function setDigest($digest)
    {
        $this->digest = $digest;
        return $this;
    }

    /**
     * @return string
     */
    public function getPadding()
    {
        return $this->padding;
    }

    /**
     * @param string $padding
     * @return XMLSecurityParams
     */
    public function setPadding($padding)
    {
        $this->padding = $padding;
        return $this;
    }

    /**
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * @param string $cipher
     * @return XMLSecurityParams
     */
    public function setCipher($cipher)
    {
        $this->cipher = $cipher;
        return $this;
    }

    /**
     * @return int
     */
    public function getKeysize()
    {
        return $this->keysize;
    }

    /**
     * @param int $keysize
     * @return XMLSecurityParams
     */
    public function setKeysize($keysize)
    {
        $this->keysize = $keysize;
        return $this;
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * @param string $hash
     * @return XMLSecurityParams
     */
    public function setHash($hash)
    {
        $this->hash = $hash;
        return $this;
    }


}
 