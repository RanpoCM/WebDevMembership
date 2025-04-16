<?php
session_start();
require_once 'db_connect.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$sql = "SELECT username, email, membership_tier, profile_picture FROM users WHERE user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email, $membership_tier, $profile_picture);
$stmt->fetch();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>My Profile | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #f9f9f9;
      color: #333;
      font-family: 'Arial', sans-serif;
    }

    .navbar {
      background-color: #212529;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      display: flex;
      justify-content: space-between;
    }

    .navbar-brand {
      color: #ff66b2 !important;
      font-weight: 600;
      display: flex;
      align-items: center;
      font-size: 1.8rem;
      cursor: default; 
    }

    .navbar-brand img {
      width: 40px;
      height: 40px;
      margin-right: 10px;
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
    
    .navbar {
      background-color:rgb(0, 0, 0);
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

    footer {
      background-color: #ff66b2;
      color: #333;
      text-align: center;
      padding: 15px;
    }

    .profile-container {
      max-width: 800px;
      margin: auto;
      padding: 40px 20px;
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
      text-align: center;
    }

    .profile-picture img {
      width: 150px;
      height: 150px;
      object-fit: cover;
      border-radius: 50%;
      border: 4px solid #ffc0cb;
    }

    .profile-info h2 {
      margin-top: 15px;
    }

    .membership-tier {
      display: inline-block;
      padding: 10px 20px;
      border-radius: 25px;
      font-weight: bold;
      margin-top: 20px;
    }

    .membership-tier.Classic {
      background-color: #ffc0cb;
      color: #333;
    }

    .membership-tier.Premium {
      background-color: #ff66b2;
      color: #fff;
    }

    .membership-tier.Trial {
      background-color: #f0ad4e;
      color: #fff;
    }

    .customer-service-section mt-4 {
      text-align: left;
    }

    .btn-pink {
      background-color: #ff69b4;
      border: none;
      color: white;
    }

    .btn-pink:hover {
      background-color: #e0569c;
    }
    .membership-tier {
  display: inline-block;
  padding: 12px 25px;
  border-radius: 30px;
  font-weight: bold;
  font-size: 1.2rem;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  animation: tierPulse 3s ease-in-out infinite;
  box-shadow: 0 0 10px rgba(255, 105, 180, 0.5);
}

.membership-tier.Classic {
  background: #ffc0cb;
  color: #000;
  box-shadow: 0 0 15px #ffc0cb;
}

.membership-tier.Premium {
  background: linear-gradient(to right, #ff66b2, #ff1493);
  color: white;
  box-shadow: 0 0 20px #ff66b2;
}

.membership-tier.Trial {
  background: #f0ad4e;
  color: white;
  box-shadow: 0 0 15px #f0ad4e;
}


@keyframes tierPulse {
  0% {
    transform: scale(1);
    box-shadow: 0 0 10px rgba(255, 105, 180, 0.5);
  }
  50% {
    transform: scale(1.05);
    box-shadow: 0 0 25px rgba(255, 105, 180, 0.8);
  }
  100% {
    transform: scale(1);
    box-shadow: 0 0 10px rgba(255, 105, 180, 0.5);
  }
}

  </style>
</head>
<script>
 
  const tier = document.querySelector('.membership-tier');

  if (tier) {
    tier.addEventListener('mouseenter', () => {
      tier.style.transform = 'scale(1.1)';
    });

    tier.addEventListener('mouseleave', () => {
      tier.style.transform = 'scale(1)';
    });
  }
</script>

<body>


<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container-fluid">
    <a class="navbar-brand" href="index.php">
      <img src="momoyo.png" alt="Momoyo Logo" />
      Momoyo
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item">
          <a class="nav-link <?php echo (basename($_SERVER['PHP_SELF']) == 'dashboard.php') ? 'active' : ''; ?>" href="dashboard.php">Dashboard</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?php echo (basename($_SERVER['PHP_SELF']) == 'profile.php') ? 'active' : ''; ?>" href="profile.php">Profile</a>
        </li>
        <li class="nav-item">
          <a class="nav-link <?php echo (basename($_SERVER['PHP_SELF']) == 'locations.php') ? 'active' : ''; ?>" href="locations.php">Locations</a>
        </li>

        <?php if (isset($_SESSION['user_id'])): ?>
          <li class="nav-item"><a class="nav-link" href="index.php">Home</a></li>
          <li class="nav-item"><a class="nav-link" href="contact.php">Contact</a></li>
          <li class="nav-item"><a class="nav-link" href="about.php">About Us</a></li>
          <li class="nav-item"><a class="nav-link" href="logout.php">Logout</a></li>
        <?php else: ?>
          <li class="nav-item"><a class="nav-link" href="login.php">Login</a></li>
          <li class="nav-item"><a class="nav-link" href="register.php">Register</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>

  <div class="container my-5">
    <div class="profile-container">
      <div class="profile-picture">
        <img src="<?php echo $profile_picture ? 'uploads/' . htmlspecialchars($profile_picture) : 'images/default-profile.jpg'; ?>" alt="Profile Picture">
      </div>

      <div class="profile-info mt-3">
        <h2><?php echo htmlspecialchars($username); ?></h2>
        <p>Email: <?php echo htmlspecialchars($email); ?></p>
        <p>Membership Tier:</p>
        <div class="membership-tier <?php echo htmlspecialchars($membership_tier); ?>">
          <?php echo htmlspecialchars($membership_tier); ?>
        </div>
      </div>

      <div class="customer-service-section mt-4">
        <h3>Customer Service</h3>
        <p>If you have any questions or need assistance, feel free to contact our support team!</p>
        <p>Email: <a href="mailto:support@momoyo.com">support@momoyo.com</a></p>
      </div>

      <div class="feedback-section mt-4">
        <h3>Feedback</h3>
        <p>We'd love to hear from you! Please share your feedback about your experience with Momoyo.</p>
        <form action="submit_feedback.php" method="POST">
          <div class="mb-3">
            <label for="feedback" class="form-label">Your Feedback</label>
            <textarea id="feedback" name="feedback" class="form-control" rows="4" required></textarea>
          </div>
          <button type="submit" class="btn btn-pink">Submit Feedback</button>
        </form>
      </div>

      <div class="settings-section mt-4">
        <h3>Settings</h3>
        <p>Manage your account settings below:</p>
        <a href="changepassword.php" class="btn btn-secondary">Change Password</a>
        <a href="updateprofile.php" class="btn btn-secondary">Update Profile</a>
      </div>
    </div>
  </div>

  <footer>
    <p>&copy; 2025 Momoyo. All rights reserved.</p>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php
$stmt->close();
$conn->close();
?>
