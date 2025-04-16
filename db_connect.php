<?php
$servername = "localhost";
$username = "root";  
$password = "";  
$dbname = "momoyo_membership";  


$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

