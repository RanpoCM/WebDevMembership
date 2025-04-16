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
  <title>About Us | Momoyo</title>
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

    .about-section {
      background-color: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      padding: 30px;
      margin-top: 30px;
    }

    .about-section h2 {
      font-size: 2rem;
      font-weight: 600;
      margin-bottom: 20px;
    }

    .about-section p {
      font-size: 1.2rem;
      line-height: 1.6;
      color: #555;
    }

    .about-img {
      max-width: 100%;
      border-radius: 8px;
      margin-bottom: 20px;
    }

    .about-us-header {
      text-align: center;
      margin-bottom: 50px;
    }

    .about-us-header h1 {
      font-size: 2.5rem;
      font-weight: 600;
      color: #333;
    }

    .about-us-header p {
      font-size: 1.2rem;
      color: #666;
    }
  </style>
</head>
<body>

  <header>
    <a class="navbar-brand text-white" href="index.php">
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
        <a class="nav-link <?php echo ($current_page == 'about.php') ? 'active' : ''; ?>" href="about.php">About Us</a>
        <li class="nav-item"><a class="nav-link" href="logout.php">Logout</a></li>
      </ul>
    </nav>
  </header>

  <section class="container py-5 about-us-header">
    <h1>About Momoyo</h1>
    <p>Welcome to the official page of Momoyo, the home of delicious ice cream and iced coffee!</p>
  </section>

  <section class="container about-section">
    <div class="row">
      <div class="col-md-6">
        <img src="momoyo.png" alt="About Momoyo" class="about-img">
      </div>
      <div class="col-md-6">
        <h2>Our Story</h2>
        <p>At Momoyo, we take pride in serving the best ice cream and iced coffee, made with love and passion. Our journey started with a single mission: to bring smiles and refreshment to our customers with every bite and sip. Over the years, we have grown, expanded our menu, and added exciting new flavors, but one thing remains the same: our commitment to quality and customer satisfaction.</p>

        <h2>Our Mission</h2>
        <p>Our mission is simple: to create unforgettable experiences with every scoop of ice cream and cup of iced coffee we serve. Whether you're here for a quick treat or a cozy hangout, we're dedicated to providing the highest quality products made with fresh ingredients. We hope that each visit to Momoyo brings joy to your day.</p>

        <h2>Our Vision</h2>
        <p>We aspire to become a beloved destination for ice cream and iced coffee enthusiasts, where people of all ages can enjoy a relaxing and flavorful experience. We envision a world where everyone can savor a sweet moment of indulgence, creating memories with friends, family, and loved ones.</p>
      </div>
    </div>
  </section>

  <footer>
    <p>&copy; 2025 Momoyo. All rights reserved.</p>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
