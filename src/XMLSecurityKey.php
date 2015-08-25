<?php
namespace RobRichards\XMLSecLibs;

use DOMElement;
use Exception;
use phpseclib\Crypt\AES;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\TripleDES;

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

    /** @var int|string */
    public $type = 0;

    /** @var mixed|null */
    public $key = null;

    /** @var string  */
    public $passphrase = "";

    /** @var string|null */
    public $iv = null;

    /** @var string|null */
    public $name = null;

    /** @var mixed|null */
    public $keyChain = null;

    /** @var bool */
    public $isEncrypted = false;

    /** @var XMLSecEnc|null */
    public $encryptedCtx = null;

    /** @var mixed|null */
    public $guid = null;

    /**
     * This variable contains the certificate as a string if this key represents an X509-certificate.
     * If this key doesn't represent a certificate, this will be null.
     * @var string|null
     */
    private $x509Certificate = null;

    /**
     * This variable contains the certificate thumbprint if we have loaded an X509-certificate.
     * @var string|null
     */
    private $X509Thumbprint = null;

    /**
     * @param string $type
     * @param null|array $params
     * @throws XMLSecurityException
     */
    public function __construct($type, $params=null)
    {
        switch ($type) {
            case (self::TRIPLEDES_CBC):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
                $this->cryptParams['keysize'] = 24;
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'DES-EDE3-CBC';
                break;
            case (self::AES128_CBC):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
                $this->cryptParams['keysize'] = 16;
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'AES-128-CBC';
                break;
            case (self::AES192_CBC):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
                $this->cryptParams['keysize'] = 24;
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'AES-192-CBC';
                break;
            case (self::AES256_CBC):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
                $this->cryptParams['keysize'] = 32;
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'AES-256-CBC';
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
                throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
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
                throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
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
                throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
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
                throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
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
            throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
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
                throw new XMLSecurityException('Certificate "type" (private/public) must be passed via parameters');
            case (self::HMAC_SHA1):
                $this->cryptParams['library'] = $type;
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
                break;
            default:
                throw new XMLSecurityException('Invalid Key Type');
        }
        $this->type = $type;
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
     * Generates a session key using the openssl-extension.
     * In case of using DES3-CBC the key is checked for a proper parity bits set - Mcrypt doesn't care about the parity bits,
     * but others may care.
     * @return string
     * @throws XMLSecurityException
     */
    public function generateSessionKey()
    {
        if (!isset($this->cryptParams['keysize'])) {
            throw new XMLSecurityException('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->cryptParams['keysize'];
        
        $key = openssl_random_pseudo_bytes($keysize);

        if ($this->type === self::TRIPLEDES_CBC) {
            /* Make sure that the generated key has the proper parity bits set.
             * Mcrypt doesn't care about the parity bits, but others may care.
            */
            for ($i = 0; $i < strlen($key); $i++) {
                $byte = ord($key[$i]) & 0xfe;
                $parity = 1;
                for ($j = 1; $j < 8; $j++) {
                    $parity ^= ($byte >> $j) & 1;
                }
                $byte |= $parity;
                $key[$i] = chr($byte);
            }
        }
        
        $this->key = $key;
        return $key;
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
     * @throws XMLSecurityException
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
            if (array_key_exists('type', $this->cryptParams) && !empty($this->cryptParams['type'])) {
                if ($this->cryptParams['type'] == 'public') {
                    if ($isCert) {
                        /* Load the thumbprint if this is an X509 certificate. */
                        $this->X509Thumbprint = self::getRawThumbprint($this->key);
                    }
                    $this->key = openssl_pkey_get_public($this->key);
                    if (!$this->key) {
                        throw new XMLSecurityException('Unable to extract public key');
                    }
                } else { //private
                    $this->key = openssl_pkey_get_private($this->key, $this->passphrase);
                }
            } else {

            }
        }
    }

    /**
     * Encrypts the given data (string) using the openssl-extension
     *
     * @param string $data
     * @return string
     * @throws Exception
     */
    private function encryptOpenSSL($data)
    {
        if (array_key_exists('type', $this->cryptParams) && !empty($this->cryptParams['type'])) {
            if ($this->cryptParams['type'] == 'public') {
                if (!openssl_public_encrypt($data, $encrypted_data, $this->key, $this->cryptParams['padding'])) {
                    throw new XMLSecurityException('Failure encrypting Data');
                }
            } else {
                if (!openssl_private_encrypt($data, $encrypted_data, $this->key, $this->cryptParams['padding'])) {
                    throw new XMLSecurityException('Failure encrypting Data');
                }
            }
        } else {
            $iv_length = openssl_cipher_iv_length($this->cryptParams['digest']);
            $this->iv = openssl_random_pseudo_bytes($iv_length);
            $data = substr($data, $iv_length);
            if (!defined('OPENSSL_RAW_DATA')) {
                $options = 1;
            } else {
                $options = OPENSSL_RAW_DATA;
            }
            $encrypted_data = openssl_encrypt($data, $this->cryptParams['digest'], $this->key, $options, $this->iv);
        }
        return $encrypted_data;
    }

    /**
     * Decrypts the given data (string) using the openssl-extension
     *
     * @param string $data
     * @return string
     * @throws Exception
     */
    private function decryptOpenSSL($data)
    {

        if (array_key_exists('type', $this->cryptParams) && !empty($this->cryptParams['type'])) {
            if ($this->cryptParams['type'] == 'public') {
                if (!openssl_public_decrypt($data, $decrypted, $this->key, $this->cryptParams['padding'])) {
                    throw new XMLSecurityException('Failure decrypting Data');
                }
            } else {
                if (!openssl_private_decrypt($data, $decrypted, $this->key, $this->cryptParams['padding'])) {
                    throw new XMLSecurityException('Failure decrypting Data');
                }
            }
        } else {
            $decrypted = $this->decryptPHPSeclib($data);
        }
        return $decrypted;
    }

    /**
     * Signs the given data (string) using the openssl-extension
     *
     * @param string $data
     * @return string
     * @throws XMLSecurityException
     */
    private function signOpenSSL($data)
    {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->cryptParams['digest'])) {
            $algo = $this->cryptParams['digest'];
        }
        if (! openssl_sign($data, $signature, $this->key, $algo)) {
            throw new XMLSecurityException('Failure Signing Data: ' . openssl_error_string() . ' - ' . $algo);
        }
        return $signature;
    }

    /**
     * Verifies the given data (string) belonging to the given signature using the openssl-extension
     *
     * @param string $data
     * @param string $signature
     * @return int
     */
    private function verifyOpenSSL($data, $signature)
    {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->cryptParams['digest'])) {
            $algo = $this->cryptParams['digest'];
        }
        return openssl_verify($data, $signature, $this->key, $algo);
    }

    /**
     * Encrypts the given data (string) using the regarding php-extension, depending on the library assigned to algorithm in the contructor.
     *
     * @param string $data
     * @return mixed|string
     */
    public function encryptData($data)
    {
        return $this->encryptOpenSSL($data);
    }

    /**
     * Decrypts the given data (string) using the regarding php-extension, depending on the library assigned to algorithm in the contructor.
     *
     * @param string $data
     * @return mixed|string
     */
    public function decryptData($data)
    {
        return $this->decryptOpenSSL($data);
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
                return $this->signOpenSSL($data);
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
                return $this->verifyOpenSSL($data, $signature);
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
     * @param string $string
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
     *
     * Hint: Modulus and Exponent must already be base64 decoded
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
     * @throws XMLSecurityException
     *
     * @return XMLSecurityKey The new key.
     */
    public static function fromEncryptedKeyElement(DOMElement $element)
    {

        $objenc = new XMLSecEnc();
        $objenc->setNode($element);
        if (! $objKey = $objenc->locateKey()) {
            throw new XMLSecurityException("Unable to locate algorithm for this Encrypted Key");
        }
        $objKey->isEncrypted = true;
        $objKey->encryptedCtx = $objenc;
        XMLSecEnc::staticLocateKeyInfo($objKey, $element);
        return $objKey;
    }

    /**
     * @param $data
     * @return String
     */
    private function decryptPHPSeclib($data)
    {
        $ivSize   = openssl_cipher_iv_length($this->cryptParams['digest']);
        $this->iv = substr($data, 0, $ivSize);
        $dataEnc  = substr($data, $ivSize);

        $digestParams = explode('-', $this->cryptParams['digest']);

        // At the moment there is only support for CBC-Mode.
        switch($digestParams[0]) {
            case 'AES':
                $lib = new AES();
                $lib->setKeyLength($digestParams[1]);
                $lib->setBlockLength(128);
                break;
            case 'DES':
                if ($digestParams[1] === 'EDE3') {
                    $lib = new TripleDES();
                } else {
                    throw new XMLSecurityException('Unsupported DES Mode: ' . $digestParams[1]);
                }
                break;
            default:
                throw new XMLSecurityException('Not supported cipher.');
        }

        $lib->setIV($this->iv);
        $lib->setKey($this->key);
        $lib->setPreferredEngine(AES::ENGINE_OPENSSL);

        $decrypted = $lib->decrypt($dataEnc);

        return $decrypted;
    }

}
