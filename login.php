<?php
require ("cofig.php");
$username = $password = "";
$username_err = $password_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (empty($_POST["username"])) {
        $username_err = "You should enter a username!!";
    } else {
        $username = trim($_POST["username"]);
    }


    if (empty($_POST["password"])){
        $password_err = "Pleaser enter your password";
    } else {
        $password = trim($_POST["password"]);
    }

    if (empty($username_err) && empty($password_err)) {

        $sql = "SELECT id, username, password FROM Users WHERE username = ?";
         if ($stmt = mysqli_prepare($link, $sql)){

             mysqli_stmt_bind_param($stmt, "s", $param_username);
             $param_username = trim($_POST["username"]);

             if (mysqli_stmt_execute($stmt)) {
                 mysqli_stmt_store_result($stmt);
                 if (mysqli_stmt_num_rows($stmt) == 1) {
                     mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                     if (mysqli_stmt_fetch($stmt)) {

                         if (password_verify($password, $hashed_password)) {
                             session_start();
                             $_SESSION["username"] = $username;
                             header("location: wlcome.php");
                         }
                     }

                 } else {
                     echo "this username doesn't exist";
                 }
             } else {
                 echo "Oops! Something went wrong. Please try again later.";
             }

             mysqli_close($link);
         }
    }




}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Log In</title>
</head>
<body>
<div>
    <h2>Log In</h2>
    <p>Please fill this form to enter your account.</p>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" aria-required="true">
            <span class="error">*<?php echo $username_err; ?></span>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" aria-required="true">
            <span class="error">*<?php echo $password_err; ?></span>
        </div>
        <div class="form-group">
            <input type="submit" value="login">
        </div>
    </form>
</div>
</body>
</html>
