<?php
session_start();
require_once 'db_connect.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];


$sql = "SELECT username, email, profile_picture FROM users WHERE user_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email, $profile_picture);
$stmt->fetch();
$stmt->close();


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $new_email = $_POST['email'];

    $new_profile_picture = $profile_picture;
    if ($_FILES['profile_picture']['error'] == 0) {
        $target_dir = "uploads/";
        $new_filename = uniqid() . "_" . basename($_FILES["profile_picture"]["name"]);
        $target_file = $target_dir . $new_filename;

        if (move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $target_file)) {
            $new_profile_picture = $new_filename;
        } else {
            $_SESSION['message'] = "Error uploading file.";
            header("Location: update_profile.php");
            exit();
        }
    }

    $sql = "UPDATE users SET email = ?, profile_picture = ? WHERE user_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ssi", $new_email, $new_profile_picture, $user_id);

    if ($stmt->execute()) {
        $_SESSION['message'] = "Profile updated successfully.";
        header("Location: profile.php");
    } else {
        $_SESSION['message'] = "Error updating profile.";
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Update Profile | Momoyo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background-color: #fff;
      color: #000;
      font-family: 'Segoe UI', sans-serif;
    }
    .container {
      max-width: 600px;
      background-color: #fff;
      border-radius: 15px;
      padding: 30px;
      box-shadow: 0 0 15px rgba(255, 192, 203, 0.3);
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
      margin-top: 10px;
      background-color: #000;
      color: #fff;
      padding: 10px 20px;
      border: none;
      border-radius: 30px;
      transition: 0.3s ease-in-out;
      text-decoration: none;
      display: inline-block;
    }
    .back-btn:hover {
      background-color: #ff69b4;
      color: #000;
      transform: scale(1.05);
    }
    .profile-preview {
      text-align: center;
      margin-bottom: 20px;
    }
    .profile-preview img {
      width: 120px;
      height: 120px;
      object-fit: cover;
      border-radius: 50%;
      border: 3px solid #ff69b4;
    }
  </style>
</head>
<body>

<div class="container my-5">
  <h2 class="text-center mb-4">Update Profile</h2>

  <?php if (isset($_SESSION['message'])): ?>
    <div class="alert alert-info text-center"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
  <?php endif; ?>

  <div class="profile-preview">
    <?php if ($profile_picture): ?>
      <img src="uploads/<?php echo htmlspecialchars($profile_picture); ?>" alt="Profile Picture">
    <?php else: ?>
      <img src="default-avatar.png" alt="Default Avatar">
    <?php endif; ?>
    <p class="mt-2"><strong><?php echo htmlspecialchars($username); ?></strong></p>
  </div>

  <form action="update_profile.php" method="POST" enctype="multipart/form-data">
    <div class="mb-3">
      <label for="email" class="form-label">Email</label>
      <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
    </div>

    <div class="mb-3">
      <label for="profile_picture" class="form-label">Change Profile Picture</label>
      <input type="file" class="form-control" id="profile_picture" name="profile_picture" accept="image/*">
    </div>

    <button type="submit" class="btn btn-primary w-100">Update Profile</button>
    <a href="profile.php" class="back-btn mt-3">← Back to Profile</a>
  </form>
</div>

</body>
</html>
