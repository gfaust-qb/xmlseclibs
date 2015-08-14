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

class XMLSecurityStrategyOpenssl extends XMLSecurityStrategyBase implements XMLSecurityStrategy
{

    /**
     * Encrypts the given data (string) using the openssl-extension
     *
     * @param string $data
     * @return mixed
     * @throws XMLSecException
     */
    public function encryptData($data)
    {
        if ($this->xmlSecurityParams->getCertificateType() == 'public') {
            if (!openssl_public_encrypt($data, $encrypted_data, $this->key, $this->xmlSecurityParams->getPadding())) {
                throw new XMLSecException('Failure encrypting Data');
            }
        } else {
            if (!openssl_private_encrypt($data, $encrypted_data, $this->key, $this->xmlSecurityParams->getPadding())) {
                throw new XMLSecException('Failure encrypting Data');
            }
        }

        return $encrypted_data;
    }

    /**
     * Decrypts the given data (string) using the openssl-extension
     *
     * @param string $data
     * @return mixed
     * @throws XMLSecException
     */
    public function decryptData($data)
    {
        if ($this->xmlSecurityParams->getCertificateType() == 'public') {
            if (!openssl_public_decrypt($data, $decrypted, $this->key, $this->xmlSecurityParams->getPadding())) {
                throw new XMLSecException('Failure decrypting Data');
            }
        } else {
            if (!openssl_private_decrypt($data, $decrypted, $this->key, $this->xmlSecurityParams->getPadding())) {
                throw new XMLSecException('Failure decrypting Data');
            }
        }

        return $decrypted;
    }

    /**
     * Generates a session key using the openssl-extension
     * @return string
     * @throws XMLSecException
     */
    public function generateSessionKey()
    {
        if ((int)$this->xmlSecurityParams->getKeysize() <= 0) {
            throw new XMLSecException('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->xmlSecurityParams->getKeysize();

        $key = openssl_random_pseudo_bytes($keysize);

        $this->key = $key;

        return $key;
    }

    /**
         * Signs the given data (string)
         *
         * @param string $data
         * @return mixed
         * @throws XMLSecException
         */
        public function signData($data)
        {
            $algo   = OPENSSL_ALGO_SHA1;
            $digest = $this->xmlSecurityParams->getDigest();
            if (! empty($digest)) {
                $algo = $digest;
            }
            if (! openssl_sign($data, $signature, $this->key, $algo)) {
                throw new XMLSecException('Failure Signing Data: ' . openssl_error_string() . ' - ' . $algo);
            }
            return $signature;
        }

        /**
         * Verifies the given data (string) belonging to the given signature
         *
         * @param string $data
         * @param string $signature
         * @return int 1 if the signature is correct, 0 if it is incorrect, and
         * -1 on error.
         */
        public function verifySignature($data, $signature)
        {
            $algo   = OPENSSL_ALGO_SHA1;
            $digest = $this->xmlSecurityParams->getDigest();
            if (! empty($digest)) {
                $algo = $digest;
            }
            return openssl_verify($data, $signature, $this->key, $algo);
        }

}
 