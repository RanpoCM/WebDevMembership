<?php
session_start();
require_once 'db_connect.php';

$current_page = basename($_SERVER['PHP_SELF']);

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Locations | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #f9f9f9;
      font-family: 'Arial', sans-serif;
      color: #333;
    }

    header {
      background-color: #000;
      color: #ff66b2;
      padding: 10px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .navbar-brand {
      color: #ff66b2;
      font-weight: bold;
      font-size: 1.8rem;
    }

    .navbar-brand img {
      width: 40px;
      height: 40px;
      animation: pulse 1.5s infinite alternate;
    }

    @keyframes pulse {
      0% { transform: scale(1); }
      50% { transform: scale(1.1); }
      100% { transform: scale(1); }
    }

    .navbar-nav .nav-link {
      color: #fff !important;
      font-weight: 500;
    }

    .nav-link.active,
    .navbar-nav .nav-link:hover {
      color: #ff66b2 !important;
    }

    .location-card {
  background: #fff;
  border: 2px solid #ff66b2;
  border-radius: 15px;
  padding: 15px;
  text-align: center;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
  height: 100%;
}

.location-card:hover {
  transform: translateY(-5px) scale(1.02);
  box-shadow: 0 8px 20px rgba(255, 102, 178, 0.3);
}

.location-card img {
  width: 100%;
  height: 200px;
  object-fit: cover;
  border-radius: 10px;
  margin-bottom: 15px;
  transition: transform 0.3s ease;
}

.location-card:hover img {
  transform: scale(1.05);
}

.location-card h4 {
  color: #ff66b2;
  margin-bottom: 10px;
}

.location-card .btn {
  background-color: #ff66b2;
  color: white;
  border: none;
  padding: 8px 20px;
  margin-top: 10px;
  transition: background-color 0.3s ease;
  border-radius: 8px;
  font-weight: 500;
}

.location-card .btn:hover {
  background-color: #e0559c;
  text-decoration: none;
}


    footer {
      background-color: #ff66b2;
      color: #fff;
      text-align: center;
      padding: 15px;
      margin-top: 40px;
    }
  </style>
</head>
<body>

  <header>
    <a class="navbar-brand text-white" href="#">
      <img src="momoyo.png" alt="Momoyo Logo" />
      Momoyo
    </a>
    <nav class="navbar navbar-expand-lg navbar-dark">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item">
          <a class="nav-link <?= $current_page === 'dashboard.php' ? 'active' : '' ?>" href="dashboard.php">Dashboard</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?= $current_page === 'profile.php' ? 'active' : '' ?>" href="profile.php">Profile</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?= $current_page === 'locations.php' ? 'active' : '' ?>" href="locations.php">Locations</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="index.php">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="contact.php">Contact</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="about.php">About Us</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="logout.php">Logout</a>
        </li>
      </ul>
    </nav>
  </header>

  <section class="container py-5">
  <h2 class="section-title text-center text-uppercase mb-4" style="color: #ff66b2;">Explore Our Locations</h2>
  <div class="row">
    <div class="col-md-4 mb-4">
      <div class="location-card">
        <img src="metroplazabranch.jpg" alt="Metro Plaza">
        <h4>Metro Plaza</h4>
        <p>Located at the heart of the city, Metro Plaza offers a modern shopping experience. Visit us for exclusive offers!</p>
        <a href="https://g.co/kgs/GVsbNMh" target="_blank" class="btn">View on Map</a>
      </div>
    </div>

    <div class="col-md-4 mb-4">
      <div class="location-card">
        <img src="smfairviewbranch.jpg" alt="SM City Fairview">
        <h4>SM City Fairview</h4>
        <p>Our branch at SM City Fairview is packed with the latest trends. Drop by for exciting promotions and events!</p>
        <a href="https://g.co/kgs/AyiAmLR" target="_blank" class="btn">View on Map</a>
      </div>
    </div>

    <div class="col-md-4 mb-4">
      <div class="location-card">
        <img src="tarlacbranch.jpg" alt="SM Tarlac">
        <h4>SM Tarlac</h4>
        <p>Our SM Tarlac branch is a great place to shop and relax. Come and enjoy our exclusive services!</p>
        <a href="https://g.co/kgs/9MyQTfT" target="_blank" class="btn">View on Map</a>
      </div>
    </div>
  </div>
</section>


  <footer>
    <p>&copy; 2025 Momoyo. All rights reserved.</p>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>