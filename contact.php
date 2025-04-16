<?php
session_start();
require_once 'db_connect.php';

$current_page = basename($_SERVER['PHP_SELF']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Contact | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #f9f9f9;
      color: #333;
      font-family: 'Arial', sans-serif;
    }

    header {
      background-color: #000;
      color: #ff66b2;
      padding: 10px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    header .navbar-brand {
      color: #ff66b2;
      font-weight: 600;
      font-size: 1.8rem;
      cursor: default; 
    }

    header .navbar-brand img {
      width: 40px;  
      height: 40px;
      animation: pulse 1.5s infinite alternate; 
    }

    @keyframes pulse {
      0% {
        transform: scale(1); 
        filter: brightness(1); 
      }
      50% {
        transform: scale(1.1); 
      }
      100% {
        transform: scale(1); 
      }
    }

    footer {
      background-color: #ff66b2;
      color: #333;
      text-align: center;
      padding: 15px;
    }

    .navbar {
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: space-between;
    }

    .navbar-nav {
      display: flex;
      flex-direction: row;
    }

    .nav-item {
      margin-left: 15px;
    }

    .nav-link {
      color: #fff !important;
      font-weight: 500;
      padding: 8px 16px;
      text-decoration: none; 
    }

    .nav-link:hover {
      color: #ff66b2 !important;
    }

    .nav-link.active {
      color: #ff66b2 !important;
      font-weight: bold;
    }

    .highlight {
      color: #ff66b2;
      font-weight: bold;
    }

    .content-section h2 {
      font-size: 1.8rem;
      font-weight: 600;
      margin-top: 30px;
    }

    .mt-4 {
      margin-top: 40px !important;
    }

    /* Social Media Section */
    .social-media-links {
      display: flex;
      flex-wrap: nowrap;
      overflow-x: auto;
      padding: 10px 0;
      gap: 15px;
    }

    .social-media-links a {
      text-decoration: none;
      font-size: 1.2rem;
      color: #333;
      padding: 10px;
      border-radius: 8px;
      background-color: #ff66b2;
      color: white;
      transition: background-color 0.3s ease;
    }

    .social-media-links a:hover {
      background-color: #c13572;
    }
  </style>
</head>
<body>

  <header>
    <a class="navbar-brand text-white" href="javascript:void(0);"> 
      <img src="momoyo.png" alt="Momoyo Logo" />
      Momoyo
    </a>
    <nav class="navbar navbar-expand-lg navbar-dark">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item">
          <a class="nav-link <?php echo ($current_page == 'dashboard.php') ? 'active' : ''; ?>" href="dashboard.php">Dashboard</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?php echo ($current_page == 'profile.php') ? 'active' : ''; ?>" href="profile.php">Profile</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?php echo ($current_page == 'locations.php') ? 'active' : ''; ?>" href="locations.php">Locations</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="index.php">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?php echo ($current_page == 'contact.php') ? 'active' : ''; ?>" href="contact.php">Contact</a>
        </li>
        
        <li class="nav-item"><a class="nav-link" href="about.php">About Us</a></li>
        <li class="nav-item"><a class="nav-link" href="logout.php">Logout</a></li>
      </ul>
    </nav>
  </header>

  <section class="container py-5">
    <h2>Contact Us</h2>
    <p>If you have any questions, feel free to reach out to us!</p>
    <p>Phone: <span class="highlight">+63 </span></p>

    
    <div class="social-media-links">
      <a href="https://www.facebook.com" target="https://www.facebook.com/MomoyoPhilippines">Facebook</a>
      <a href="https://www.instagram.com" target="https://www.instagram.com/momoyo_philippines/#">Instagram</a>
    </div>

  </section>

  <footer>
    <p>&copy; 2025 Momoyo. All rights reserved.</p>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
