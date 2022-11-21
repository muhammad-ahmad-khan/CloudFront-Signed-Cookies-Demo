<?php

require 'vendor/autoload.php';

use Aws\Credentials\Credentials;
use Aws\SecretsManager\SecretsManagerClient;
use Aws\CloudFront\CloudFrontClient;
use Aws\Exception\AwsException;

// Check if user is login or check if user is paid the fee


// Initialize AWS credentials from IAM role
$credentials_uri = getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');
$credentials_url = 'http://169.254.170.2' . $credentials_uri;
$get_credentials = file_get_contents($credentials_url);
$credentials_array = json_decode($get_credentials, true);
$credentials = new Credentials($credentials_array["AccessKeyId"], $credentials_array["SecretAccessKey"], $credentials_array["Token"], strtotime($credentials_array["Expiration"]));

// Create a Secrets Manager Client
$secretManagerClient = new SecretsManagerClient([
    'credentials' => $credentials,
    'version' => '2017-10-17',
    'region' => 'us-east-1',
]);

$secretName = 'private-content-access-key';

try {
    $secretResult = $secretManagerClient->getSecretValue([
        'SecretId' => $secretName,
    ]);

}
catch (AwsException $e) {
    // output error message if fails
    echo $e->getAwsErrorMessage();
    echo "\n";
}


function signCookie($cloudFrontClient, $policy, $privateKey, $keyPairId)
{
    try {
        $result = $cloudFrontClient->getSignedCookie([
            'policy' => $policy,
            'private_key' => $privateKey,
            'key_pair_id' => $keyPairId
        ]);

        return $result;

    }
    catch (AwsException $e) {
        return ['Error' => $e->getAwsErrorMessage()];
    }
}

function signACookie($privateKey)
{
    $resourcePath = 'https://content.mysite.com/private-content/*';
    $expires = time() + 3600; // 60 minutes (60 * 60 seconds) from now.
    $keyPairId = 'ABCDWXYZ';
    $policy =
    '{'.
        '"Statement":['.
            '{'.
                '"Resource":"'. $resourcePath . '",'.
                '"Condition":{'.
                    '"DateLessThan":{"AWS:EpochTime":' . $expires . '}'.
                '}'.
            '}'.
        ']' .
    '}';

    $cloudFrontClient = new CloudFrontClient([
        'credentials' => $credentials,
        'version' => '2014-11-06',
        'region' => 'us-east-1'
    ]);

    $result = signCookie(
        $cloudFrontClient,
        $policy,
        $privateKey,
        $keyPairId
    );

    $cookies = array();

    foreach ($result as $key => $value) {
        array_push(
            $cookies,
            array(
            'name' => $key,
            'value' => $value,
            'expires' => $expires,
            'path' => '/',
            'domain' => ".mysite.com",
            'secure' => true,
            'httpOnly' => true
        )
        );

    }

    foreach ($cookies as $cookie) {
        setcookie
            (
            $cookie['name'],
            $cookie['value'],
            $cookie['expires'],
            $cookie['path'],
            $cookie['domain'],
            $cookie['secure'],
            $cookie['httpOnly']
        );
    }
}

if (isset($secretResult['SecretString'])) {
    $privateKey = $secretResult['SecretString'];
    signACookie($privateKey);
}

// Give access to the content e.g https://content.mysite.com/private-content/doc.pdf
