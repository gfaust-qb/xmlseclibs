<?php
namespace RobRichards\XMLSecLibs;

use DOMElement;
use Exception;

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

class XMLSecurityKey
{
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    const HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';

    /** @var array */
    private $cryptParams = array();

    /** @var XMLSecurityStrategy  */
    private $xmlSecurityStrategy = null;

    /** @var int|string */
    public $type = 0;

    /** @var mixed|null */
    public $key = null;

    /** @var string  */
    public $passphrase = "";

    /** @var string  */
    public $iv = null;

    /** @var string */
    public $name = null;

    /**
     * @var mixed|null
     * @deprecated
     */
    public $keyChain = null;

    /** @var bool */
    public $isEncrypted = false;

    /** @var XMLSecEnc */
    public $encryptedCtx = null;

    /** @var mixed|null */
    public $guid = null;

    /**
     * This variable contains the certificate as a string if this key represents an X509-certificate.
     * If this key doesn't represent a certificate, this will be null.
     */
    private $x509Certificate = null;

    /* This variable contains the certificate thumbprint if we have loaded an X509-certificate. */
    private $X509Thumbprint = null;

    /**
     * @param string $type
     * @param null|array $params
     */
    public function __construct($type, $params=null)
    {
        switch ($type) {
            case (self::TRIPLEDES_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_TRIPLEDES;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
                $this->cryptParams['keysize'] = 24;
                break;
            case (self::AES128_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
                $this->cryptParams['keysize'] = 16;
                break;
            case (self::AES192_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
                $this->cryptParams['keysize'] = 24;
                break;
            case (self::AES256_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
                $this->cryptParams['keysize'] = 32;
                break;
            case (self::RSA_1_5):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_OAEP_MGF1P):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
                $this->cryptParams['hash'] = null;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA1):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA256):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA384):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA384';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA512):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA512';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecException('Certificate "type" (private/public) must be passed via parameters');
            case (self::HMAC_SHA1):
                $this->cryptParams['library'] = $type;
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
                break;
            default:
                throw new XMLSecException('Invalid Key Type');
        }
        $this->type = $type;

        $this->xmlSecurityStrategy = new XMLSecurityStrategyFactory($this->type, new XMLSecurityParams($this->cryptParams));
    }

    /**
     * Retrieve the key size for the symmetric encryption algorithm..
     *
     * If the key size is unknown, or this isn't a symmetric encryption algorithm,
     * null is returned.
     *
     * @return int|null  The number of bytes in the key.
     */
    public function getSymmetricKeySize()
    {
        if (! isset($this->cryptParams['keysize'])) {
            return null;
        }
        return $this->cryptParams['keysize'];
    }

    /**
     * Generates a session key using the openssl-extension or using the mcrypt-extension as a fallback.
     * In case of using DES3-CBC the key is checked for a proper parity bits set - Mcrypt doesn't care about the parity bits,
     * but others may care.
     * @return string
     * @throws \Exception
     */
    public function generateSessionKey()
    {
        return $this->xmlSecurityStrategy->generateSessionKey();
    }

    /**
     * Get the raw thumbprint of a certificate
     *
     * @param string $cert
     * @return null|string
     */
    public static function getRawThumbprint($cert)
    {

        $arCert = explode("\n", $cert);
        $data = '';
        $inData = false;

        foreach ($arCert AS $curData) {
            if (! $inData) {
                if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0) {
                    $inData = true;
                }
            } else {
                if (strncmp($curData, '-----END CERTIFICATE', 20) == 0) {
                    break;
                }
                $data .= trim($curData);
            }
        }

        if (! empty($data)) {
            return strtolower(sha1(base64_decode($data)));
        }

        return null;
    }

    /**
     * Loads the given key, or - with isFile set true - the key from the keyfile.
     *
     * @param string $key
     * @param bool $isFile
     * @param bool $isCert
     * @throws \Exception
     */
    public function loadKey($key, $isFile=false, $isCert = false)
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
            $this->key = $str_cert;
        } else {
            $this->x509Certificate = null;
        }
        if ($this->cryptParams['library'] == 'openssl') {
            if ($this->cryptParams['type'] == 'public') {
                if ($isCert) {
                    /* Load the thumbprint if this is an X509 certificate. */
                    $this->X509Thumbprint = self::getRawThumbprint($this->key);
                }
                $this->key = openssl_pkey_get_public($this->key);
                if (! $this->key) {
                    throw new XMLSecException('Unable to extract public key');
                }
            } else {
                $this->key = openssl_pkey_get_private($this->key, $this->passphrase);
            }
        } else if ($this->cryptParams['cipher'] == MCRYPT_RIJNDAEL_128) {
            /* Check key length */
            switch ($this->type) {
                case (self::AES256_CBC):
                    if (strlen($this->key) < 25) {
                        throw new XMLSecException('Key must contain at least 25 characters for this cipher');
                    }
                    break;
                case (self::AES192_CBC):
                    if (strlen($this->key) < 17) {
                        throw new XMLSecException('Key must contain at least 17 characters for this cipher');
                    }
                    break;
            }
        }
    }

    /**
     * Encrypts the given data (string) using the regarding php-extension, depending on the library assigned to algorithm in the contructor.
     *
     * @param string $data
     * @return mixed|string
     */
    public function encryptData($data)
    {
        return $this->xmlSecurityStrategy->encryptData($data);
    }

    /**
     * Decrypts the given data (string) using the regarding php-extension, depending on the library assigned to algorithm in the contructor.
     *
     * @param $data
     * @return mixed|string
     */
    public function decryptData($data)
    {
        return $this->xmlSecurityStrategy->decryptData($data);
    }

    /**
     * Signs the data (string) using the extension assigned to the type in the constructor.
     *
     * @param string $data
     * @return mixed|string
     */
    public function signData($data)
    {
        switch ($this->cryptParams['library']) {
            case 'openssl':
                return $this->xmlSecurityStrategy->signData($data);
            case (self::HMAC_SHA1):
                return hash_hmac("sha1", $data, $this->key, true);
        }
    }

    /**
     * Verifies the data (string) against the given signature using the extension assigned to the type in the constructor.
     * @param string $data
     * @param string $signature
     * @return bool|int
     */
    public function verifySignature($data, $signature)
    {
        switch ($this->cryptParams['library']) {
            case 'openssl':
                return $this->xmlSecurityStrategy->verifySignature($data, $signature);
            case (self::HMAC_SHA1):
                $expectedSignature = hash_hmac("sha1", $data, $this->key, true);
                return strcmp($signature, $expectedSignature) == 0;
        }
    }

    /**
     * @deprecated
     * @see getAlgorithm()
     * @return mixed
     */
    public function getAlgorith()
    {
        return $this->getAlgorithm();
    }

    /**
     * @return mixed
     */
    public function getAlgorithm()
    {
        return $this->cryptParams['method'];
    }

    /**
     *
     * @param int $type
     * @param $string
     * @return null|string
     */
    public static function makeAsnSegment($type, $string)
    {
        switch ($type) {
            case 0x02:
                if (ord($string) > 0x7f)
                    $string = chr(0).$string;
                break;
            case 0x03:
                $string = chr(0).$string;
                break;
        }

        $length = strlen($string);

        if ($length < 128) {
            $output = sprintf("%c%c%s", $type, $length, $string);
        } else if ($length < 0x0100) {
            $output = sprintf("%c%c%c%s", $type, 0x81, $length, $string);
        } else if ($length < 0x010000) {
            $output = sprintf("%c%c%c%c%s", $type, 0x82, $length / 0x0100, $length % 0x0100, $string);
        } else {
            $output = null;
        }
        return $output;
    }

    /**
     * @hint Modulus and Exponent must already be base64 decoded
     * @param string $modulus
     * @param string $exponent
     * @return string
     */
    public static function convertRSA($modulus, $exponent)
    {
        /* make an ASN publicKeyInfo */
        $exponentEncoding = self::makeAsnSegment(0x02, $exponent);
        $modulusEncoding = self::makeAsnSegment(0x02, $modulus);
        $sequenceEncoding = self::makeAsnSegment(0x30, $modulusEncoding.$exponentEncoding);
        $bitstringEncoding = self::makeAsnSegment(0x03, $sequenceEncoding);
        $rsaAlgorithmIdentifier = pack("H*", "300D06092A864886F70D0101010500");
        $publicKeyInfo = self::makeAsnSegment(0x30, $rsaAlgorithmIdentifier.$bitstringEncoding);

        /* encode the publicKeyInfo in base64 and add PEM brackets */
        $publicKeyInfoBase64 = base64_encode($publicKeyInfo);
        $encoding = "-----BEGIN PUBLIC KEY-----\n";
        $offset = 0;
        while ($segment = substr($publicKeyInfoBase64, $offset, 64)) {
            $encoding = $encoding.$segment."\n";
            $offset += 64;
        }
        return $encoding."-----END PUBLIC KEY-----\n";
    }

    /**
     * @deprecated
     * @param mixed $parent
     */
    public function serializeKey($parent)
    {

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
     * Get the thumbprint of this X509 certificate.
     *
     * Returns:
     *  The thumbprint as a lowercase 40-character hexadecimal number, or null
     *  if this isn't a X509 certificate.
     *
     *  @return string Lowercase 40-character hexadecimal number of thumbprint
     */
    public function getX509Thumbprint()
    {
        return $this->X509Thumbprint;
    }


    /**
     * Create key from an EncryptedKey-element.
     *
     * @param DOMElement $element The EncryptedKey-element.
     *
     * @return XMLSecurityKey The new key.
     */
    public static function fromEncryptedKeyElement(DOMElement $element)
    {

        $objenc = new XMLSecEnc();
        $objenc->setNode($element);
        if (! $objKey = $objenc->locateKey()) {
            throw new XMLSecException("Unable to locate algorithm for this Encrypted Key");
        }
        $objKey->isEncrypted = true;
        $objKey->encryptedCtx = $objenc;
        XMLSecEnc::staticLocateKeyInfo($objKey, $element);
        return $objKey;
    }

}
