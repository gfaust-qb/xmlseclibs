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

class XMLSecurityStrategyMcrypt extends XMLSecurityStrategyBase implements XMLSecurityStrategy
{

    /**
     * Encrypts the given data (string) using the mcrypt-extension
     *
     * @param string $data
     * @return string
     */
    public function encryptData($data)
    {
        $td       = mcrypt_module_open($this->xmlSecurityParams->getCipher(), '', $this->xmlSecurityParams->getMode(), '');
        $this->iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $this->key, $this->iv);
        if ($this->xmlSecurityParams->getMode() == MCRYPT_MODE_CBC) {
            $bs = mcrypt_enc_get_block_size($td);
            for ($datalen0 = $datalen = strlen($data); (($datalen % $bs) != ($bs - 1)); $datalen++)
                $data .= chr(mt_rand(1, 127));
            $data .= chr($datalen - $datalen0 + 1);
        }
        $encrypted_data = $this->iv . mcrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);

        return $encrypted_data;
    }

    /**
     * Decrypts the given data (string) using the mcrypt-extension
     *
     * @param string $data
     * @return string
     */
    public function decryptData($data)
    {
        $td        = mcrypt_module_open($this->xmlSecurityParams->getCipher(), '', $this->xmlSecurityParams->getMode(), '');
        $iv_length = mcrypt_enc_get_iv_size($td);

        $this->iv = substr($data, 0, $iv_length);
        $data     = substr($data, $iv_length);

        mcrypt_generic_init($td, $this->key, $this->iv);
        $decrypted_data = mdecrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        if ($this->xmlSecurityParams->getMode() == MCRYPT_MODE_CBC) {
            $dataLen        = strlen($decrypted_data);
            $paddingLength  = substr($decrypted_data, $dataLen - 1, 1);
            $decrypted_data = substr($decrypted_data, 0, $dataLen - ord($paddingLength));
        }

        return $decrypted_data;
    }

    /**
     * Generates a session key using the mcrypt-extension.
     * In case of using DES3-CBC the key is checked for a proper parity bits set - Mcrypt doesn't care about the parity bits,
     * but others may care.
     * @return string
     * @throws XMLSecException
     */
    public function generateSessionKey()
    {
        if ((int)$this->xmlSecurityParams->getKeysize() <= 0) {
            throw new XMLSecException('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->xmlSecurityParams->getKeysize();

        /* Generating random key using iv generation routines */
        $key = mcrypt_create_iv($keysize, MCRYPT_RAND);

        if ($this->type === XMLSecurityKey::TRIPLEDES_CBC) {
            /* Make sure that the generated key has the proper parity bits set.
             * Mcrypt doesn't care about the parity bits, but others may care.
            */
            for ($i = 0; $i < strlen($key); $i++) {
                $byte   = ord($key[$i]) & 0xfe;
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
}
 