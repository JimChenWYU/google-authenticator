<?php

namespace JimChen\GoogleAuthenticator;

class TOTPAlgorithm
{
    /**
     * Return code length
     *
     * @var int
     */
    protected $codeLength = 6;

    /**
     * Generate a keyed hash value using the HMAC method
     *
     * @var string
     */
    protected $hashAlgo = 'SHA1';

    /**
     * Calculate the code, with given secret and point in time.
     *
     * @param string   $secret
     * @param int|null $timeSlice
     *
     * @return string
     */
    public function getCode($secret, $timeSlice = null)
    {
        if ($timeSlice === null) {
            $timeSlice = (int)floor(time() / 30);
        }

        $secretkey = Helper::base32Encode($secret);

        // Pack time into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac($this->hashAlgo, $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = 10 ** $this->codeLength;

        return str_pad($value % $modulo, $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string   $secret
     * @param string   $code
     * @param int      $discrepancy      This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $currentTimeSlice time slice if we want use other that time()
     *
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1, $currentTimeSlice = null)
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = (int)floor(time() / 30);
        }

        if (strlen($code) != $this->codeLength) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if (Helper::timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6.
     *
     * @param int $length
     *
     * @return static
     */
    public function setCodeLength($length)
    {
        $this->codeLength = $length;

        return $this;
    }

    /**
     * SHA1
     *
     * @return $this
     */
    public function setSha1HashAlgo()
    {
        $this->hashAlgo = 'SHA1';

        return $this;
    }

    /**
     * SHA256
     *
     * @return $this
     */
    public function setSha256HashAlgo()
    {
        $this->hashAlgo = 'SHA256';

        return $this;
    }

    /**
     * SHA512
     *
     * @return $this
     */
    public function setSha512HashAlgo()
    {
        $this->hashAlgo = 'SHA512';

        return $this;
    }
}
