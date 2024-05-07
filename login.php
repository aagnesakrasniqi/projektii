<?php
session_start();
include_once('admin/includes/connect.php');

$errors = array();

if (isset($_POST['submit'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirmPassword'];
    $email = $_POST['email'];

    if (empty($username)) {
        array_push($errors, "Username is required");
    } elseif (!preg_match("/^[a-zA-ZëË ]*$/", $username)) {
        array_push($errors, "Only letters and white space allowed");
    }

    if (empty($email)) {
        array_push($errors, "Email is required");
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        array_push($errors, "Invalid email format");
    }

    if (empty($password)) {
        array_push($errors, "Password is required");
    }
    if($password != $confirmPassword){
        array_push($errors, "Password nuk eshte i njejt");
    }

    // Check if username or email already exists
    $query = "SELECT * FROM users WHERE username=:username OR email=:email";
    $checkQuery = $conn->prepare($query);
    $checkQuery->bindParam(':username', $username);
    $checkQuery->bindParam(':email', $email);
    $checkQuery->execute();
    $result = $checkQuery->fetchAll();

    foreach ($result as $row) {
        if ($row['username'] == $username) {
            array_push($errors, "Username already exists");
        }
        if ($row['email'] == $email) {
            array_push($errors, "Email already exists");
        }
    }

    if (count($errors) == 0) {
        // Hash the password before storing it
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $sql = "INSERT INTO users (username, password, email) VALUES (:username, :password, :email)";
        $sqlQuery = $conn->prepare($sql);

        $sqlQuery->bindParam(':username', $username);
        $sqlQuery->bindParam(':password', $hashedPassword);
        $sqlQuery->bindParam(':email', $email);

        $sqlQuery->execute();

        echo "<script>alert('Register succesfully!')</script>";
    }
}


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
            if($result['role']==1)
            {
            echo "<script>alert('Login successful!')</script>";
            echo "<script>window.open('index.php','_self')</script>";
            }
            else{
                echo "<script>alert('Login successful!')</script>";
                echo "<script>window.open('user.php','_self')</script>";
            }
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
    <link rel="stylesheet" href="admin/assets/css/login.css?v=<?php echo time(); ?>">

</head>

<body>
    <div class="main">
        <input type="checkbox" id="chk" aria-hidden="true">
        <?php  if (count($errors) > 0) { ?>
             <div class="error">
        <?php foreach ($errors as $error) { ?>
        <p><?php echo $error ?></p>
        <?php } ?>
    </div>

    <?php  } ?>
        <div class="signup">
            <form method="post">
                <label for="chk" aria-hidden="true">Sign up</label>
                <input type="text" name="username" placeholder="Username" required="">
                <input type="email" name="email" placeholder="Email" required="">
                <input type="password" name="password" placeholder="Password" required="">
                <input type="password" name="confirmPassword" placeholder="Confirm Password" required="">
    

                <button name="submit">Sign up</button>
            </form>
        </div>

        <div class="login">
            <form method="post">
                <label for="chk" aria-hidden="true">Login</label>
                <input type="text" name="username" placeholder="Username" required="">
                <input type="password" name="password" placeholder="Password" required="">
                <button type="submit" name="login">Login</button>
            </form>
        </div>
    </div>
</body>

</html>