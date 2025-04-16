<?php
include 'db.php'; 

$tier = isset($_GET['tier']) ? $_GET['tier'] : 'Free';
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Register | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link rel="stylesheet" href="styles.css" />
  <style>
    body, html {
      margin: 0;
      padding: 0;
      height: 100%;
      display: flex;
      justify-content: center;
      align-items: center;
      width: 100%;
    }

    .login-container {
      display: flex;
      height: 100%;
      width: 100%;
    }

    .left-side {
      flex: 1;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: rgba(255, 255, 255, 0.9); 
      padding: 30px;
      height: 100%; 
    }

    .right-side {
      flex: 1;
      background-image: url('Momoyobg.png'); 
      background-size: cover;
      background-position: center;
      height: 100%;
    }


    @keyframes pulse {
      0% {
        transform: scale(1);
      }
      50% {
        transform: scale(1.1);
      }
      100% {
        transform: scale(1);
      }
    }

    .logo {
      display: block;
      margin: 0 auto 20px;
      width: 150px;
      animation: pulse 1.5s infinite ease-in-out; 
      transition: all 0.3s ease-in-out; 
      border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    }

    .logo:hover {
      transform: scale(1.05); 
      box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2); 
    }

    .form-container {
      background-color: white;
      border-radius: 15px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
      padding: 30px;
      width: 100%;
      max-width: 400px;
    }

    h2 {
      font-size: 1.8rem;
      font-weight: 600;
      color: #212529;
      margin-bottom: 20px;
    }

    .form-control {
      border-radius: 10px;
      padding: 15px;
      margin-bottom: 15px;
      font-size: 1rem;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
    }

    .form-control:focus {
      box-shadow: 0 0 5px rgba(0, 0, 0, 0.15);
    }

    .btn {
      padding: 12px 25px;
      border-radius: 30px;
      font-size: 1.2rem;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
      transition: transform 0.3s ease, background-color 0.3s ease;
    }

    .btn-primary {
      background-color: rgb(255, 122, 189);
      border-color: #d63384;
    }

    .btn-primary:hover {
      background-color: #c13572;
      transform: scale(1.05);
    }

    .mt-4 p a {
      font-size: 1rem;
      color: #fff;  
      text-decoration: none; 
      background-color: #d63384; 
      padding: 10px 25px; 
      border-radius: 30px; 
      transition: background-color 0.3s ease, transform 0.3s ease; 
    }

    .mt-4 p a:hover {
      background-color: #c13572; 
      transform: scale(1.05); 
      text-decoration: none; 
    }

    .alert {
      margin-bottom: 20px;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(-20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

  </style>
</head>
<body>

<section class="login-container">
  
  <div class="left-side">
    <div class="form-container">
      <img src="momoyo.png" alt="Momoyo Logo" class="logo">

      <h2 class="text-center mb-4">Create Your Momoyo Account</h2>

      <?php session_start(); ?>
      <?php if (isset($_SESSION['error'])): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
          <?= $_SESSION['error']; unset($_SESSION['error']); ?>
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      <?php endif; ?>

      <?php if (isset($_SESSION['success'])): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
          <?= $_SESSION['success']; unset($_SESSION['success']); ?>
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      <?php endif; ?>

      <form action="register_action.php" method="POST" enctype="multipart/form-data">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" id="username" name="username" required>
        </div>
        <div class="mb-3">
          <label for="email" class="form-label">Email</label>
          <input type="email" class="form-control" id="email" name="email" required>
        </div>
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <div class="mb-3">
          <label for="confirm_password" class="form-label">Confirm Password</label>
          <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
        </div>
        <div class="mb-3">
          <label for="profile_picture" class="form-label">Profile Picture</label>
          <input type="file" class="form-control" id="profile_picture" name="profile_picture" accept="image/*">
        </div>
        <button type="submit" class="btn btn-primary">Register</button>
      </form>

      <div class="mt-4 text-center">
        <p>Already have an account? <a href="login.php">Log in here</a></p>
      </div>
    </div>
  </div>

  <div class="right-side"></div>
</section>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
