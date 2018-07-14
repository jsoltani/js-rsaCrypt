<?php
/**
 * RsaCrypt - The main class
 *
 * @author    javad soltani <j.soltani.it@gmail.com>
 * @copyright 2015 Dmitry Mamontov <d.slonyara@gmail.com>
 * @license   http://www.opensource.org/licenses/BSD-3-Clause  The BSD 3-Clause License
 */
class jsRsaCrypt
{
    /**
     * Path to the keys.
     * @var string
     * @access protected
     */
    protected $private, $public;

    /**
     * Checks for the required functions for encryption.
     * @throws Exception
     * @return void
     * @access public
     * @final
     */
    final public function __construct()
    {
        if (
            function_exists('openssl_get_publickey') === false ||
            function_exists('openssl_public_encrypt') === false ||
            function_exists('openssl_get_privatekey') === false ||
            function_exists('openssl_private_decrypt') === false
        ) {
            throw new Exception('Not all the functions of openssl.');
        }
    }

    /**
     * It generates private and public keys with the specified size.
     * @param integer $size
     * @return boolean
     * @access public
     * @final
     * @throws Exception
     */
    final public function genKeys($size = 2048)
    {
        if (function_exists('exec') == false) {
            throw new Exception('Exec function not used.');
        }
        if (in_array($size, array(512, 1024, 2048)) === false) {
            throw new Exception('The key size can only be 512 bits, 1024 bits or 2048 bits. 2048 bits is recommended.');
        }

        @exec(
            "openssl genrsa -out " .
            __DIR__ . "/private.pem $size 2>&1 && openssl rsa -in " .
            __DIR__ . "/private.pem -out " .
            __DIR__ . "/public.pem -outform PEM -pubout 2>&1",
            $out,
            $status
        );

        if ($status == -1) {
            throw new Exception('Error generating keys. Check the settings for openssl.');
        }

        $this->public = 'public.pem';
        $this->private = 'private.pem';

        return true;
    }

    /**
     * Initializes public key.
     * @param string $key
     * @return boolean
     * @access public
     * @final
     * @throws Exception
     */
    final public function setPublicKey($key)
    {
        if (is_null($key) || empty($key) || file_exists($key) === false) {
            throw new Exception('Wrong key.');
        }

        $this->public = $key;

        return true;
    }

    /**
     * Gets public key.
     * @return boolean
     * @access public
     * @final
     */
    final public function getPublicKey()
    {
        return is_null($this->public) ? false : $this->public;
    }

    /**
     * Initializes private key.
     * @param string $key
     * @return mixed
     * @access public
     * @final
     * @throws Exception
     */
    final public function setPrivateKey($key)
    {
        if (is_null($key) || empty($key) || file_exists($key) === false) {
            throw new Exception('Wrong key.');
        }

        $this->private = $key;

        return true;
    }

    /**
     * Gets private key.
     * @return mixed
     * @access public
     * @final
     */
    final public function getPrivateKey()
    {
        return is_null($this->private) ? false : $this->private;
    }

    /**
     * Data encryption.
     * @param string $data
     * @return mixed
     * @access public
     * @final
     * @throws Exception
     */
    final public function encrypt($data)
    {
        if (is_null($data) || empty($data) || is_string($data) === false) {
            throw new Exception('Needless to encrypt.');
        } elseif (is_null($this->public) || empty($this->public)) {
            throw new Exception('You need to set the public key.');
        }

        $key = @file_get_contents($this->public);
        if ($key) {
            $key = openssl_get_publickey($key);
            openssl_public_encrypt($data, $encrypted, $key);

            return chunk_split(self::jsBase64Encode($encrypted));
        }

        return false;
    }

    /**
     * Decrypt data.
     * @param string $data
     * @return mixed
     * @access public
     * @final
     * @throws Exception
     */
    final public function decrypt($data)
    {
        if (is_null($data) || empty($data) || is_string($data) === false) {
            throw new Exception('Needless to encrypt.');
        } elseif (is_null($this->private) || empty($this->private)) {
            throw new Exception('You need to set the private key.');
        }

        $key = @file_get_contents($this->private);
        if ($key) {
            $key = openssl_get_privatekey($key);
            openssl_private_decrypt(self::jsBase64Decode($data), $result, $key);

            return $result;
        }
    }

    /**
     * jsBase64Encode
     * for encode base64 data
     *
     * @param string $data
     *
     * @return string
     */
    private static function jsBase64Encode($data) {
        return rtrim(str_replace(array('+', '/'), array('-', '_'), base64_encode($data)), '=');
    }

    /**
     * jsBase64Decode
     * for decode base64 data
     *
     * @param string $data
     *
     * @return string
     */
    private static function jsBase64Decode($data) {
        return base64_decode(str_replace(array('-', '_'), array('+', '/'), $data));
    }
}
