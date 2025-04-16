<?php
session_start();
require_once 'db_connect.php';

$current_tier = 'Free'; 

if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $query = "SELECT membership_tier FROM users WHERE user_id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->bind_result($membership_tier);
    if ($stmt->fetch()) {
        $current_tier = $membership_tier;
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Membership Tiers | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: white;
      font-family: 'Segoe UI', sans-serif;
      color: #000;
    }

    .navbar {
      background-color: #000;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
      position: relative;
    }

    .logo-container {
      display: flex;
      justify-content: center;
      align-items: center;
      animation: logoFadeIn 2s ease-out;
    }

    .logo {
      width: 120px;
      height: auto;
      border-radius: 10px;
      transition: all 0.5s ease-in-out;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1);
      animation: pulse 1.5s infinite ease-in-out;
    }

    @keyframes pulse {
      0% { transform: scale(1); }
      50% { transform: scale(1.1); }
      100% { transform: scale(1); }
    }

    @keyframes logoFadeIn {
      from { opacity: 0; transform: scale(0.8); }
      to { opacity: 1; transform: scale(1); }
    }

    .logo:hover {
      transform: scale(1.05);
      box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
      border-radius: 15px;
    }

    .navbar-brand {
      display: flex;
      align-items: center;
    }

    .navbar-brand img {
      height: 50px;
      margin-right: 10px;
    }

    .navbar-brand span {
      color: #fff;
      font-size: 1.5rem;
    }

    .tier-card {
      background: #fff;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
      transition: transform 0.3s, box-shadow 0.3s;
      margin-top: 20px;
    }

    .tier-card:hover {
      transform: translateY(-10px);
      box-shadow: 0 15px 30px rgba(0, 0, 0, 0.2);
    }

    .tier-title {
      font-size: 1.75rem;
      color: #fff;
      margin-bottom: 15px;
      text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.3);
    }

    .tier-description {
      font-size: 1rem;
      color: #fff;
      margin-bottom: 20px;
      text-shadow: 1px 1px 3px rgba(0, 0, 0, 0.3);
    }

    .benefit-item {
      font-size: 1.1rem;
      color: #fff;
    }

    .btn-upgrade {
      color: #fff;
      padding: 10px 20px;
      border-radius: 30px;
      text-decoration: none;
      display: inline-block;
      transition: all 0.3s ease;
    }

    .btn-upgrade:hover {
      transform: scale(1.05);
      opacity: 0.9;
    }

    .badge {
      font-size: 1rem;
    }


    .tier-free {
      background: linear-gradient(135deg, #ff4081, #f50057);
    }

    .tier-classic {
      background: linear-gradient(135deg, #00bcd4, #00796b);
    }

    .tier-premium {
      background: linear-gradient(135deg, #4caf50, #388e3c);
    }

   
    .btn-upgrade-free {
      background-color: #ff4081;
    }

    .btn-upgrade-classic {
      background-color: #00bcd4;
    }

    .btn-upgrade-premium {
      background-color: #4caf50;
    }
    .back-btn {
  padding: 12px 30px;
  font-size: 1.25rem;
  border-radius: 50px;
  transition: all 0.3s ease;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
  animation: backPulse 1.5s infinite alternate;
}

.back-btn:hover {
  transform: translateY(-3px) scale(1.05);
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
  background-color: #ff4081;
  color: white;
}

@keyframes backPulse {
  from {
    transform: scale(1);
  }
  to {
    transform: scale(1.03);
  }
}


  </style>
</head>
<body>

<nav class="navbar navbar-dark shadow-sm">
  <a class="navbar-brand d-flex align-items-center" href="index.php">
    <div class="logo-container">
      <img src="momoyo.png" alt="Momoyo Logo" class="logo">
      <h1>Momoyo Iced Cream and Iced Coffee</h1>
    </div>
  </a>
</nav>

<?php if (isset($_SESSION['message'])): ?>
  <div class="alert alert-info text-center mt-3"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
<?php endif; ?>

<section class="py-5">
  <div class="container">
    <h2 class="text-center section-heading mb-2">Membership Tiers</h2>
    <p class="text-center section-sub mb-5">Choose the membership that suits you and enjoy amazing benefits at Momoyo!</p>
<div class="text-center mb-4">
  <button class="btn btn-dark btn-lg back-btn" onclick="history.back()">← Back</button>
</div>

 
    <div class="row g-4">

      <div class="col-md-4">
        <div class="tier-card text-center tier-free">
          <h3 class="tier-title">Free</h3>
          <p class="tier-description">Get started with our loyalty card and stamps!</p>
          <ul class="list-unstyled mb-4">
            <li class="benefit-item"> Loyalty Card</li>
            <li class="benefit-item"> Stamp Rewards</li>
          </ul>
          <?php if (!isset($_SESSION['user_id'])): ?>
            <a href="register.php" class="btn-upgrade btn-upgrade-free">Join Now</a>
          <?php elseif ($current_tier === 'Free'): ?>
            <span class="badge bg-success">Current Tier</span>
          <?php else: ?>
            <span class="badge bg-secondary">Included</span>
          <?php endif; ?>
        </div>
      </div>

      <div class="col-md-4">
        <div class="tier-card text-center tier-classic">
          <h3 class="tier-title">Classic</h3>
          <p class="tier-description">Enjoy discounts and exclusive scratch cards!</p>
          <ul class="list-unstyled mb-4">
            <li class="benefit-item">₱5 Discount</li>
            <li class="benefit-item"> Scratch Cards</li>
          </ul>
          <?php if ($current_tier === 'Free'): ?>
            <form action="payment_options.php" method="POST">
              <input type="hidden" name="new_tier" value="Classic">
              <button type="submit" class="btn-upgrade btn-upgrade-classic">Upgrade to Classic</button>
            </form>
          <?php elseif ($current_tier === 'Classic'): ?>
            <span class="badge bg-success">Current Tier</span>
          <?php else: ?>
            <span class="badge bg-secondary">Included in Premium</span>
          <?php endif; ?>
        </div>
      </div>

      <div class="col-md-4">
        <div class="tier-card text-center tier-premium">
          <h3 class="tier-title">Premium</h3>
          <p class="tier-description">Access exclusive discounts and special scratch cards!</p>
          <ul class="list-unstyled mb-4">
            <li class="benefit-item">₱10 Discount</li>
            <li class="benefit-item">Exclusive Scratch Cards</li>
          </ul>
          <?php if ($current_tier === 'Premium'): ?>
            <span class="badge bg-success">Current Tier</span>
          <?php else: ?>
            <form action="payment_options.php" method="POST">
              <input type="hidden" name="new_tier" value="Premium">
              <button type="submit" class="btn-upgrade btn-upgrade-premium">Upgrade to Premium</button>
            </form>
          <?php endif; ?>
        </div>
      </div>

    </div>
  </div>
</section>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
