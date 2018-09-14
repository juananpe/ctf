<?php

define('KEY', "ooghie1Z Fae8aish OhT3fie6 Gae2aiza");

function sign($data) {
  return hash_hmac('md5', $data, KEY);
}


function respond_with($data) {
  header("Content-Type: application/json;");
  echo json_encode($data);
  die();
}

?>
