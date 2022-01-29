<?php
session_start();
?>
<html>
<body>
<?php

require ("cofig.php");

$sql = "SELECT id, username FROM Users WHERE username = ?";

if($stmt = mysqli_prepare($link, $sql)){

    mysqli_stmt_bind_param($stmt, "s", $param_username);

    $param_username = $_SESSION["username"];

    if(mysqli_stmt_execute($stmt)){
        echo "Welcome here " . $_SESSION["username"];
    } else {
        echo "Oops! Something went wrong. Please try again later.";
    }
    mysqli_stmt_close($stmt);
}
?>
</body>
</html>