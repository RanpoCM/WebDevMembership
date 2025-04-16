<?php
session_start();
require_once 'db_connect.php';

function generate_hash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

$password_changed = false;

if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $current_password = $_POST['current_password'];
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];

        if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
            $_SESSION['message'] = "All fields are required.";
            header("Location: change_password.php");
            exit();
        }

        if ($new_password !== $confirm_password) {
            $_SESSION['message'] = "New password and confirm password do not match.";
            header("Location: change_password.php");
            exit();
        }

        $sql = "SELECT password FROM users WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->bind_result($hashed_password);
        $stmt->fetch();
        $stmt->close();

        if (!password_verify($current_password, $hashed_password)) {
            $_SESSION['message'] = "Current password is incorrect.";
            header("Location: change_password.php");
            exit();
        }

        $new_hashed_password = generate_hash($new_password);

        $sql = "UPDATE users SET password = ? WHERE user_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("si", $new_hashed_password, $user_id);

        if ($stmt->execute()) {
            $password_changed = true;
            session_destroy(); 
        } else {
            $_SESSION['message'] = "Error changing password.";
            header("Location: change_password.php");
            exit();
        }

        $stmt->close();
    }
} else {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Change Password | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet" />
  <style>
    body {
      background-color: #fff0f5;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .momoyo-btn {
      background-color: #ff69b4;
      color: #fff;
      border: none;
      padding: 10px 25px;
      font-weight: bold;
      border-radius: 30px;
      transition: 0.3s ease;
      text-decoration: none;
      display: inline-block;
      margin-top: 10px;
      box-shadow: 0 4px 12px rgba(255, 105, 180, 0.3);
    }
    .momoyo-btn:hover {
      background-color: #e0559e;
      transform: scale(1.05);
      color: #fff;
      box-shadow: 0 6px 18px rgba(255, 105, 180, 0.5);
    }
    .momoyo-btn i {
      margin-right: 6px;
    }
  </style>
</head>
<body>

<div class="container my-5">
  <h2>Change Password</h2>

  <?php if (isset($_SESSION['message'])): ?>
    <div class="alert alert-info">
      <?php 
        echo $_SESSION['message']; 
        unset($_SESSION['message']); 
      ?>
    </div>
  <?php endif; ?>

  <?php if ($password_changed): ?>
    <div class="alert alert-success">
      <p><strong>Successfully changed the password.</strong> Please log in again.</p>
      <a href="login.php" class="btn momoyo-btn">
        <i class="bi bi-box-arrow-in-right"></i> Login
      </a>
    </div>
  <?php else: ?>
    <form action="change_password.php" method="POST">
      <div class="mb-3">
        <label for="current_password" class="form-label">Current Password</label>
        <input type="password" class="form-control" id="current_password" name="current_password" required>
      </div>

      <div class="mb-3">
        <label for="new_password" class="form-label">New Password</label>
        <input type="password" class="form-control" id="new_password" name="new_password" required>
      </div>

      <div class="mb-3">
        <label for="confirm_password" class="form-label">Confirm New Password</label>
        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
      </div>

      <button type="submit" class="btn momoyo-btn">Change Password</button>
    </form>
  <?php endif; ?>
</div>

</body>
</html>
