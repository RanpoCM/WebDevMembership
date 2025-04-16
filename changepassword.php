<?php
session_start();
require_once 'db_connect.php';

function generate_hash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

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
        $_SESSION['message'] = "Password changed successfully.";
        header("Location: profile.php");
    } else {
        $_SESSION['message'] = "Error changing password.";
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Change Password | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #fff;
      font-family: 'Segoe UI', sans-serif;
      color: #000;
    }

    .container {
      max-width: 550px;
      margin-top: 60px;
      padding: 40px;
      background-color: #ffffff;
      box-shadow: 0 0 20px rgba(255, 105, 180, 0.2);
      border-radius: 15px;
    }

    h2 {
      text-align: center;
      margin-bottom: 30px;
      font-weight: 700;
      color: #ff69b4;
    }

    .form-label {
      font-weight: 600;
    }

    .btn-primary {
      background-color: #ff69b4;
      border: none;
      font-weight: 600;
    }

    .btn-primary:hover {
      background-color: #ff1493;
    }

    .back-btn {
      background-color: #000;
      color: #fff;
      border: none;
      padding: 10px 20px;
      border-radius: 25px;
      text-decoration: none;
      display: inline-block;
      margin-top: 15px;
      transition: all 0.3s ease-in-out;
    }

    .back-btn:hover {
      background-color: #ff69b4;
      color: #000;
      transform: scale(1.05);
    }
  </style>
</head>
<body>

<div class="container">
  <h2>Change Password</h2>

  <?php if (isset($_SESSION['message'])): ?>
    <div class="alert alert-info text-center"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
  <?php endif; ?>

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

    <button type="submit" class="btn btn-primary w-100">Change Password</button>
    <a href="profile.php" class="back-btn d-block text-center">← Back to Profile</a>
  </form>
</div>

</body>
</html>
