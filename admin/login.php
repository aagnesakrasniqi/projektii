<?php
session_start();
include('includes/connect.php');

$errors = array();

if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validation and Sanitization
    $username = htmlspecialchars($username);

    if (empty($username) || empty($password)) {
        array_push($errors, "Both username and password are required for login");
    }

    if (count($errors) == 0) {
        $query = "SELECT * FROM users WHERE username=:username";
        $checkQuery = $conn->prepare($query);
        $checkQuery->bindParam(':username', $username);
        $checkQuery->execute();
        $result = $checkQuery->fetch();

        if ($result && password_verify($password, $result['password'])) {
            // Login successful
            $_SESSION['username'] = $username;
            echo "<script>alert('Login successful!')</script>";
            echo "<script>window.open('index.php','_self')</script>";
        } else {
            array_push($errors, "Invalid username or password");
            echo "<script>alert('Invalid username or password')</script>";
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>CodePen - Sign up / Login Form</title>
    <link rel="stylesheet" href="assets/css/login.css?v=<?php echo time(); ?>">

</head>

<body>
    <div class="main">
        <input type="checkbox" id="chk" aria-hidden="true">

        <div class="signup">
            <form method="post">
                <label for="chk" aria-hidden="true">Sign up</label>
                <input type="text" name="txt" placeholder="User name" required="">
                <input type="email" name="email" placeholder="Email" required="">
                <input type="password" name="pswd" placeholder="Password" required="">
                <button>Sign up</button>
            </form>
        </div>

        <div class="login">
            <form method="post">
                <label for="chk" aria-hidden="true">Login</label>
                <input type="text" name="username" placeholder="Username" required="">
                <input type="password" name="password" placeholder="Password" required="">
                <button name="login">Login</button>
            </form>
        </div>
    </div>
</body>

</html>