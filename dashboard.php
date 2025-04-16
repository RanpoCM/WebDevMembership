<?php
session_start();
require_once 'db_connect.php';

$current_page = basename($_SERVER['PHP_SELF']);

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];

$sql = "SELECT username, membership_tier, profile_picture FROM users WHERE user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $membership_tier, $profile_picture);
$stmt->fetch();
$stmt->close();

$sql_payment_status = "SELECT status, payment_date FROM payments WHERE user_id = ? ORDER BY payment_date DESC LIMIT 1";
$stmt_payment = $conn->prepare($sql_payment_status);
$stmt_payment->bind_param("i", $user_id);
$stmt_payment->execute();
$stmt_payment->bind_result($payment_status, $payment_date);
$stmt_payment->fetch();
$stmt_payment->close();

$sql_payment_history = "SELECT amount, status, payment_date FROM payments WHERE user_id = ? ORDER BY payment_date DESC";
$stmt_history = $conn->prepare($sql_payment_history);
$stmt_history->bind_param("i", $user_id);
$stmt_history->execute();
$stmt_history->store_result();
$stmt_history->bind_result($payment_amount, $payment_status_history, $payment_date_history);
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dashboard | Momoyo</title>
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

    .profile-section {
      display: flex;
      align-items: center;
      margin-top: 30px;
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      padding: 20px;
    }

    .profile-section img {
      border-radius: 50%;
      margin-right: 20px;
    }

    .profile-section h1 {
      font-size: 2rem;
      margin-bottom: 10px;
    }

    .profile-section p {
      font-size: 1.2rem;
    }

    .alert {
      font-size: 1.1rem;
      padding: 15px;
      margin-bottom: 20px;
    }

    .btn-custom {
      padding: 12px 25px;
      font-size: 1.1rem;
      border-radius: 25px;
      background-color: #ff66b2;
      color: #fff;
      transition: background-color 0.3s ease;
      display: inline-block;
      text-align: center;
      text-decoration: none; 
    }

    .btn-custom:hover {
      background-color: #c13572;
    }

    .payment-table th, .payment-table td {
      text-align: center;
      vertical-align: middle;
    }

    .payment-table th {
      background-color: #ff66b2;
      color: white;
    }

    .payment-table tr:hover {
      background-color:rgba(241, 241, 241, 0.24);
    }

    .content-section h2 {
      font-size: 1.8rem;
      font-weight: 600;
      margin-top: 30px;
    }

    .mt-4 {
      margin-top: 40px !important;
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
    </nav>
  </header>

  <section class="container py-5">
    <div class="profile-section">
      <img src="<?php echo $profile_picture ? 'uploads/' . htmlspecialchars($profile_picture) : 'images/default-profile.jpg'; ?>" alt="Profile Picture" width="150" height="150">
      <div>
        <h1>Welcome, <?php echo htmlspecialchars($username); ?>!</h1>
        <p>Your Membership Tier: <span class="highlight"><?php echo htmlspecialchars($membership_tier); ?></span></p>
      </div>
    </div>

    <div class="mt-4">
      <h2>Payment Status</h2>
      <?php if ($payment_status): ?>
        <p>Last payment status: <strong><?php echo htmlspecialchars($payment_status); ?></strong></p>
        <p>Payment Date: <?php echo date('F j, Y, g:i a', strtotime($payment_date)); ?></p>
      <?php else: ?>
        <p>No payment made yet. Please complete your payment to access exclusive content.</p>
      <?php endif; ?>
    </div>

    <div class="mt-4">
      <h2>Notifications</h2>
      <?php if ($membership_tier == 'Premium'): ?>
        <div class="alert alert-success" role="alert">
          You have exclusive access to Premium content!
        </div>
      <?php else: ?>
        <div class="alert alert-warning" role="alert">
          Upgrade to <strong>Premium</strong> to unlock exclusive content and features!
        </div>
      <?php endif; ?>
    </div>

    <div class="mt-4">
    <h2>Upgrade your Membership</h2>
    <a href="membershiptiers.php" class="btn-custom">Upgrade Now</a>
</div>

    <div class="mt-4">
      <h2>Payment History</h2>
      <table class="table payment-table">
        <thead>
          <tr>
            <th>Amount</th>
            <th>Status</th>
            <th>Payment Date</th>
          </tr>
        </thead>
        <tbody>
          <?php if ($stmt_history->num_rows > 0): ?>
            <?php while ($stmt_history->fetch()): ?>
              <tr>
                <td>₱<?php echo number_format($payment_amount, 2); ?></td>
                <td><?php echo htmlspecialchars($payment_status_history); ?></td>
                <td><?php echo date('F j, Y, g:i a', strtotime($payment_date_history)); ?></td>
              </tr>
            <?php endwhile; ?>
          <?php else: ?>
            <tr>
              <td colspan="3">No payment history found.</td>
            </tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>

    <div class="content-section mt-4">
      <?php if ($membership_tier == 'Premium'): ?>
        <h2>Exclusive Premium Content</h2>
        <p>Enjoy your exclusive content as a Premium member!</p>
      <?php else: ?>
        <h2>Exclusive Content</h2>
        <p>Upgrade to <strong>Premium</strong> to access exclusive content!</p>
      <?php endif; ?>
    </div>
  </section>

  <footer>
    <p>&copy; 2025 Momoyo. All rights reserved.</p>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

<?php
$stmt_history->close();
?>
