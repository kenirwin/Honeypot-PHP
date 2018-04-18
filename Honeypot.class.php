<?php
class Honeypot {
    public function __construct() {
        $this->db_connect();
    }

    private function db_connect() {
        try {
            $this->db = new PDO('mysql:host='.DB_HOST.';dbname='.DB_DB.';charset='.DB_CHARSET, DB_USER, DB_PASS);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $ex) {
            print ($ex->getMessage());
        }
    }

    public function Log($ip, $error, $url, $referrer) {
        $datetime = date('Y-m-d H:i:s');
        try {
            $stmt = $this->db->prepare('INSERT INTO honeypot_log(error_time,error_code,ip,target_url,referrer) VALUES (:time,:code,:ip,:url,:referrer)');
            $stmt->execute(array(':time'=>$datetime,
                                 ':code'=>$error,
                                 ':ip'=>$ip,
                                 ':url'=>$url,
                                 ':referrer'=>$referrer));
        } catch (PDOException $ex) {
            print ($ex->getMessage());
        }
    }
}