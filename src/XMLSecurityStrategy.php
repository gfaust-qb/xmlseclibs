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

interface XMLSecurityStrategy
{

    /**
     * @param string $data
     * @return mixed
     */
    public function encryptData($data);

    /**
     * @param string $data
     * @return mixed
     */
    public function decryptData($data);

    /**
     * @param string $data
     * @return mixed
     */
    public function signData($data);

    /**
     * @param string $data
     * @param string $signature
     * @return mixed
     */
    public function verifySignature($data, $signature);

    /**
     * @return mixed
     */
    public function generateSessionKey();

    /**
     * Loads the given key, or - with isFile set true - the key from the keyfile.
     *
     * @param string $key
     * @param bool $isFile
     * @param bool $isCert
     * @throws \Exception
     */
    public function loadKey($key, $isFile = false, $isCert = false);

    /**
     * @param string $passphrase
     * @return mixed
     */
    public function setPassphrase($passphrase);

    /**
     * @return mixed
     */
    public function getPassphrase();

    /**
     * @param string|null $key
     * @return mixed
     */
    public function setKey($key);

    /**
     * @return mixed
     */
    public function getKey();

    /**
     * Get the thumbprint of this X509 certificate.
     *
     * Returns:
     *  The thumbprint as a lowercase 40-character hexadecimal number, or null
     *  if this isn't a X509 certificate.
     *
     * @return string Lowercase 40-character hexadecimal number of thumbprint
     */
    public function getX509Thumbprint();

    /**
     * Retrieve the X509 certificate this key represents.
     *
     * Will return the X509 certificate in PEM-format if this key represents
     * an X509 certificate.
     *
     * @return string The X509 certificate or null if this key doesn't represent an X509-certificate.
     */
    public function getX509Certificate();

}
