<?php
class S3
{

	private static $__accessKey = null; // AWS Access key
	private static $__secretKey = null; // AWS Secret key
	private static $__useSSL = false;
	private static $__endpoint = 's3.amazonaws.com';	
	
/**
* Initializer
*
* @param string $accessKey Access key
* @param string $secretKey Secret key
* @param boolean $useSSL Enable SSL
* @return void
*/
public static function init($accessKey = null, $secretKey = null, $useSSL = false, $endpoint = 's3.amazonaws.com')
{
if ($accessKey !== null && $secretKey !== null)
  self::setAuth($accessKey, $secretKey);
self::$__useSSL = $useSSL;
self::$__endpoint = $endpoint;
}

/**
* Set AWS access key and secret key
*
* @param string $accessKey Access key
* @param string $secretKey Secret key
* @return void
*/
public static function setAuth($accessKey, $secretKey)
{
self::$__accessKey = $accessKey;
self::$__secretKey = $secretKey;
}

/**
* Creates a HMAC-SHA1 hash
*
* This uses the hash extension if loaded
*
* @internal Used by __getSignature()
* @param string $string String to sign
* @return string
*/
private static function __getHash($string)
{
return base64_encode(extension_loaded('hash') ?
hash_hmac('sha1', $string, self::$__secretKey, true) : pack('H*', sha1(
(str_pad(self::$__secretKey, 64, chr(0x00)) ^ (str_repeat(chr(0x5c), 64))) .
pack('H*', sha1((str_pad(self::$__secretKey, 64, chr(0x00)) ^
(str_repeat(chr(0x36), 64))) . $string)))));
}


/**
* Get a query string authenticated URL
*
* @param string $bucket Bucket name
* @param string $uri Object URI
* @param integer $lifetime Lifetime in seconds
* @param boolean $hostBucket Use the bucket name as the hostname
* @param boolean $https Use HTTPS ($hostBucket should be false for SSL verification)
* @return string
*/
public static function getAuthenticatedURL($bucket, $uri, $lifetime, $hostBucket = false)
{
$expires = time() + $lifetime;
$uri = str_replace('%2F', '/', rawurlencode($uri)); // URI should be encoded (thanks Sean O'Dea)
return sprintf((self::$__useSSL ? 'https' : 'http').'://%s/%s?AWSAccessKeyId=%s&Expires=%u&Signature=%s',
$hostBucket ? $bucket : $bucket . '.' . self::$__endpoint, $uri, self::$__accessKey, $expires,
urlencode(self::__getHash("GET\n\n\n{$expires}\n/{$bucket}/{$uri}")));
}
}

// EXAMPLE:
//S3::setAuth("awsAccessKey", "awsSecretKey");
//echo S3::getAuthenticatedURL("yogamamadvd", "DVD1.AVI", 24*60*60 /* 1d */); 
?>
