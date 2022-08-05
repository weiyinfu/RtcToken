<?php

$Privileges = array(
    "PrivPublishStream" => 0,

    // not exported, do not use directly
    "privPublishAudioStream" => 1,
    "privPublishVideoStream" => 2,
    "privPublishDataStream" => 3,

    "PrivSubscribeStream" => 4,
);

$VERSION = "001";
$VERSION_LENGTH = 3;
$APP_ID_LENGTH = 24;



class AccessToken
{
    public $appID, $appKey, $roomID, $userID;
    public $issuedAt, $nonce, $expireAt, $privileges;

    // New initializes token struct by required parameters.
    public static function init($appID, $appKey, $roomID, $userID)
    {
        $token = new AccessToken();

        $token->appID = $appID;
        $token->appKey = $appKey;
        $token->roomID = $roomID;
        $token->userID = $userID;

        $token->issuedAt = now();
        $token->nonce = rand(0, 100000);
        $token->expireAt = 0;
        $token->privileges = array();

        return $token;
    }

    // AddPrivilege adds permission for token with an expiration.
    public function addPrivilege($key, $expireTimestamp)
    {
        $this->privileges[$key] = $expireTimestamp;
        GLOBAL $Privileges;

        if ($key === $Privileges["PrivPublishStream"]){
            $this->privileges[$Privileges["privPublishAudioStream"]] = $expireTimestamp;
            $this->privileges[$Privileges["privPublishVideoStream"]] = $expireTimestamp;
            $this->privileges[$Privileges["privPublishDataStream"]] = $expireTimestamp;
        }
        return $this;
    }

    // ExpireTime sets token expire time, won't expire by default.
    // The token will be invalid after expireTime no matter what privilege's expireTime is.
    public function expireTime($expireTimestamp)
    {
        $this->expireAt = $expireTimestamp;
        return $this;
    }

    public function packMsg()
    {
        $buffer = unpack("C*", pack("V", $this->nonce));
        $buffer = array_merge($buffer, unpack("C*", pack("V", $this->issuedAt)));
        $buffer = array_merge($buffer, unpack("C*", pack("V", $this->expireAt)));
        $buffer = array_merge($buffer, unpack("C*", packString($this->roomID)));
        $buffer = array_merge($buffer, unpack("C*", packString($this->userID)));

        $buffer = array_merge($buffer, unpack("C*", pack("v", sizeof($this->privileges))));

        sort($this->privileges);
        foreach ($this->privileges as $key => $value) {
            $buffer = array_merge($buffer, unpack("C*", pack("v", $key)));
            $buffer = array_merge($buffer, unpack("C*", pack("V", $value)));
        }
        return $buffer;
    }

    // Serialize generates the token string
    public function serialize()
    {
        $msg = $this->packMsg();
        $signature = hash_hmac('sha256', implode(array_map("chr", $msg)), $this->appKey, true);
        $content = array_merge(unpack("C*", pack("v", count($msg))), $msg, unpack("C*", packString($signature)));
        GLOBAL $VERSION;
        $ret = $VERSION . $this->appID . base64_encode(implode(array_map("chr", $content)));
        return $ret;
    }

    // Verify checks if this token valid, called by server side.
    public function verify($key)
    {
        if ($this->expireAt > 0 && now > $this->expireAt){
            return false;
        }
        $this->appKey = $key;
        return $this->signature === hash_hmac('sha256', implode(array_map("chr", $this->packMsg())), $this->appKey, true);
    }

    // Parse retrieves token information from raw string
    public static function parse($raw){
        GLOBAL $VERSION, $VERSION_LENGTH, $APP_ID_LENGTH;
        if (strlen($raw) <= $VERSION_LENGTH+$APP_ID_LENGTH){
            return;
        }
        if (substr($raw, 0, $VERSION_LENGTH) !== $VERSION){
            return;
        }

        $token = new AccessToken();
        $token->appID = substr($raw, $VERSION_LENGTH, $APP_ID_LENGTH);
        $content = (base64_decode(substr($raw, $VERSION_LENGTH + $APP_ID_LENGTH, strlen($raw) - ($VERSION_LENGTH + $APP_ID_LENGTH))));

        $pos = 0;
        $len = unpack("v", $content.substr($pos, 2))[1];
        $pos += 2;
        $msg = substr($content, $pos, $len);

        $pos += $len;
        $sigLen = unpack("v", substr($content, $pos, 2))[1];
        $pos += 2;
        $token->signature = substr($content, $pos, $sigLen);


        $p = 0;
        $token->nonce = unpack("V", substr($msg, $p, 4))[1];
        $p += 4;
        $token->issuedAt = unpack("V", substr($msg, $p, 4))[1];
        $p += 4;
        $token->expireAt = unpack("V", substr($msg, $p, 4))[1];
        $p += 4;
        $roomLen = unpack("v", substr($msg, $p, 2))[1];
        $p += 2;
        $token->roomID = substr($msg, $p, $roomLen);
        $p += $roomLen;
        $uidLen = unpack("v", substr($msg, $p, 2))[1];
        $p += 2;
        $token->userID = substr($msg, $p, $uidLen);
        $p += $uidLen;
        $size = unpack("v", substr($msg, $p, 2))[1];
        $p += 2;
        $privileges = array();
        for($i = 0; $i < $size; $i++){
            $key = unpack("v", substr($msg, $p, 2));
            $p += 2;
            $value = unpack("V", substr($msg, $p, 4));
            $p += 4;
            $privileges[$key[1]] = $value[1];
        }
        $token->privileges = $privileges;

        return $token;
    }

}


function packString($value)
{
    return pack("v", strlen($value)) . $value;
}

function now()
{
    date_default_timezone_set("UTC");
    $date = new DateTime();
    return $date->getTimestamp();
}