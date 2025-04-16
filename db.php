<?php
$host = "localhost";
$username = "root";
$password = "";
$dbname = "momoyo_membership";

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

