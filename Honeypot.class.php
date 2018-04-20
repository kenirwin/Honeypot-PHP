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
            print '<li>'.$ex->getMessage().' in '.$ex->getFile().' on line '.$ex->getLine().'</li>';
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
            print '<li>'.$ex->getMessage().' in '.$ex->getFile().' on line '.$ex->getLine().'</li>';
        }
    }
    
    public function CheckLog() {
        try {
            if (MATCHING_OCTETS == 4) {
                $iprange = 'ip as iprange';
            }
            elseif (MATCHING_OCTETS == 3) {
                $iprange = "CONCAT(SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  1), '.', -1),'.',SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  2), '.', -1),'.',SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  3), '.', -1),'.*') as IPrange";
            }
            elseif (MATCHING_OCTETS == 2) {
                $iprange = "CONCAT(SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  1), '.', -1),'.',SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  2), '.', -1),'.*.*') as IPrange";
            }
            elseif (MATCHING_OCTETS == 1) {
                $iprange = "CONCAT(SUBSTRING_INDEX(SUBSTRING_INDEX(`ip`, '.',  1), '.', -1),'.*.*.*') as IPrange";
            }

            $query = "SELECT ".$iprange.",count(*) as hits FROM `honeypot_log` WHERE error_time > date_add(CURRENT_TIMESTAMP, INTERVAL ? minute) GROUP by iprange";
            print "<li>$query</li>";
            $stmt = $this->db->prepare($query);
            $minutes = 0 - CHECK_MINUTES;
            $stmt->execute(array($minutes));
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                if ($row['hits'] > BAN_THRESHOLD) {
                    $this->BanIP($row['IPrange']);
                }
            }
        } catch (PDOException $ex) {
            print '<li>'.$ex->getMessage().' in '.$ex->getFile().' on line '.$ex->getLine().'</li>';
        }
        
    }

    private function BanIP($ip) {
        try { 
            $stmt = $this->db->prepare('INSERT IGNORE INTO `honeypot_ips` (ip,ban_date) VALUES(?,?)');
            $date = date('Y-m-d');
            $stmt->execute(array($ip,$date));
            print "<li>Added IP $ip to Banned list";
        } catch (PDOException $ex) {
            print '<li>'.$ex->getMessage().' in '.$ex->getFile().' on line '.$ex->getLine().'</li>';
        }
    }


    public function PurgeLog() {
        try {
            $stmt = $this->db->query('DELETE FROM `honeypot_log` WHERE DATE(error_time) = DATE(NOW() - INTERVAL 1 DAY)');
            print "<li>Yestday's Log DELETED</li>";
        } catch (PDOException $ex) { 
            print '<li>'.$ex->getMessage().' in '.$ex->getFile().' on line '.$ex->getLine().'</li>';
        }
    }
}