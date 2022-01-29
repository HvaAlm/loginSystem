<?php
session_start();
require("cofig.php");

$username = $email = $password = $confirm_password = "";
$username_err = $email_err = $password_err = $confirm_password_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){

    if(empty(trim($_POST["username"]))){
        $username_err = "<br>Please enter a username.";
    } elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))){
        $username_err = "Username can only contain letters, numbers, and underscores.";
    } else{

        $sql = "SELECT id FROM Users WHERE username = ?";

        if($stmt = mysqli_prepare($link, $sql)){

            mysqli_stmt_bind_param($stmt, "s", $param_username);

            $param_username = trim($_POST["username"]);

            if(mysqli_stmt_execute($stmt)){

                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "<br>This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                    $_SESSION["username"] = trim(($_POST["username"]));
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
            mysqli_stmt_close($stmt);
        }
    }

    if (empty(trim($_POST["email"]))){
        $email_err = "<br>Please enter an email.";
    } else {
        $email = trim($_POST["email"]);
        $_SESSION["email"] = trim($_POST["email"]);
    }

    if(empty(trim($_POST["password"]))){
        $password_err = "<br>Please enter a password.";
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "<br>Password must have at least 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }

    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "<br>Please confirm password.";
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "<br>Password did not match.";
        }
    }

    if(empty($username_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)){


        $sql = "INSERT INTO Users (username, email, password) VALUES (?, ?, ?)";

        if($stmt = mysqli_prepare($link, $sql)){

            mysqli_stmt_bind_param($stmt, "sss", $param_username, $param_email, $param_password);


            $param_username = $username;
            $param_email = $email;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash


            if(mysqli_stmt_execute($stmt)){

                header("location: wlcome.php");
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }


            mysqli_stmt_close($stmt);
        }
    }


    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
</head>
<body>
<div>
    <h2>Sign Up</h2>
    <p>Please fill this form to create an account.</p>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" aria-required="true">
            <span class="error">*<?php echo $username_err; ?></span>
        </div>
        <div class="form_group">
            <label>Email</label>
            <input type="email" name="email" aria-required="true">
            <span class="error">*<?php echo $email_err;?></span>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" aria-required="true">
            <span class="error">*<?php echo $password_err; ?></span>
        </div>
        <div class="form-group">
            <label>Confirm Password</label>
            <input type="password" name="confirm_password" aria-required="true">
            <span class="error">*<?php echo $confirm_password_err; ?></span>
        </div>
        <div class="form-group">
            <input type="submit" class="btn btn-primary" value="sign up">
        </div>

        <a href="login.php">login</a>
    </form>
</div>
</body>
</html>