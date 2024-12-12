<?php
$servername = "localhost";
$username = "root";
$password = "p@ssw0rd";
$dbname = "exemplo";




$conn = mysqli_connect($servername, $username, $password, $dbname);
mysqli_set_charset($conn, "utf8mb4");
if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
}
;
?>