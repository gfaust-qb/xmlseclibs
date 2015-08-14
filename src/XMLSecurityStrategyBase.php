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

class XMLSecurityStrategyBase {

    /** @var XMLSecurityParams */
    protected $xmlSecurityParams = null;

    /** @var string */
    protected $key = '';

    /** @var string */
    protected $iv = '';

    /** @var string|null */
    protected $passphrase = null;

    /** @var string|null */
    protected $x509Certificate = null;

    /** @var string|null */
    protected $X509Thumbprint = null;

    /**
     * @param XMLSecurityParams $xmlSecurityParams
     */
    public function __construct(XMLSecurityParams $xmlSecurityParams)
    {
        $this->xmlSecurityParams = $xmlSecurityParams;
    }

    /**
     * @param string $iv
     */
    public function setIv($iv)
    {
        $this->iv = $iv;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @param string $key
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param XMLSecurityParams $xmlSecurityParams
     */
    public function setXmlSecurityParams(XMLSecurityParams $xmlSecurityParams)
    {
        $this->xmlSecurityParams = $xmlSecurityParams;
    }

    /**
     * @return XMLSecurityParams
     */
    public function getXmlSecurityParams()
    {
        return $this->xmlSecurityParams;
    }

    /**
     * @param string $data
     */
    public function encryptData($data)
    {

    }

    /**
     * @param string $data
     */
    public function decryptData($data)
    {

    }

    /**
     * Loads the given key, or - with isFile set true - the key from the keyfile.
     *
     * @param string $key
     * @param bool $isFile
     * @param bool $isCert
     * @throws \Exception
     */
    public function loadKey($key, $isFile = false, $isCert = false)
    {
        if ($isFile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }
        if ($isCert) {
            $this->key = openssl_x509_read($this->key);
            openssl_x509_export($this->key, $str_cert);
            $this->x509Certificate = $str_cert;
            $this->key             = $str_cert;
        } else {
            $this->x509Certificate = null;
        }
        if ($this->xmlSecurityParams->getLibrary() == XMLSecurityKey::PHP_EXTENSION_OPENSSL) {
            if ($this->xmlSecurityParams->getCertificateType() == 'public') {
                if ($isCert) {
                    /* Load the thumbprint if this is an X509 certificate. */
                    $this->X509Thumbprint = XMLSecurityKey::getRawThumbprint($this->key);
                }
                $this->key = openssl_pkey_get_public($this->key);
                if (!$this->key) {
                    throw new XMLSecException('Unable to extract public key');
                }
            } else {
                $this->key = openssl_pkey_get_private($this->key, $this->getPassphrase());
            }
        } else if ($this->xmlSecurityParams->getCipher() == MCRYPT_RIJNDAEL_128) {
            /* Check key length */
            switch ($this->xmlSecurityParams->getMethod()) {
                case (XMLSecurityKey::AES256_CBC):
                    if (strlen($this->key) < 25) {
                        throw new XMLSecException('Key must contain at least 25 characters for this cipher');
                    }
                    break;
                case (XMLSecurityKey::AES192_CBC):
                    if (strlen($this->key) < 17) {
                        throw new XMLSecException('Key must contain at least 17 characters for this cipher');
                    }
                    break;
            }
        }
    }

    /**
     * Set passphrase to null if it is unset.
     * @param null|string $passphrase
     */
    public function setPassphrase($passphrase)
    {
        $this->passphrase = $passphrase;
    }

    /**
     * Returns null for an unset passphrase.
     * @return null|string
     */
    public function getPassphrase()
    {
        return $this->passphrase;
    }

    /**
     * Retrieve the X509 certificate this key represents.
     *
     * Will return the X509 certificate in PEM-format if this key represents
     * an X509 certificate.
     *
     * @return string The X509 certificate or null if this key doesn't represent an X509-certificate.
     */
    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }

    /**
     * @param null|string $x509Certificate
     */
    public function setX509Certificate($x509Certificate)
    {
        $this->x509Certificate = $x509Certificate;
    }

    /**
     * Get the thumbprint of this X509 certificate.
     *
     * Returns:
     *  The thumbprint as a lowercase 40-character hexadecimal number, or null
     *  if this isn't a X509 certificate.
     *
     * @return string Lowercase 40-character hexadecimal number of thumbprint
     */
    public function getX509Thumbprint()
    {
        return $this->X509Thumbprint;
    }

    /**
     * @param null|string $X509Thumbprint
     */
    public function setX509Thumbprint($X509Thumbprint)
    {
        $this->X509Thumbprint = $X509Thumbprint;
    }

    /**
     * @param string $data
     * @return mixed|void
     */
    public function signData($data)
    {

    }

    public function verifySignature($data, $signature)
    {

    }

}
 