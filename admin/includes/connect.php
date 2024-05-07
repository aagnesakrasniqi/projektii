<?php

$user="root";
$pass="";
$server="localhost";
$dbname="projektifinal";

try {
	
	$conn =new PDO("mysql:host=$server;dbname=$dbname",$user,$pass);
	 echo "connected";

} catch (PDOException $e) {
	echo "error: " . $e->getMessage();
}
?>