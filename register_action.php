<?php
session_start();
require_once 'db_connect.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if ($password !== $confirm_password) {
        echo "Passwords do not match.";
        exit();
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    $profile_picture = null;
    if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] == 0) {
        $target_dir = "uploads/";
        $target_file = $target_dir . basename($_FILES["profile_picture"]["name"]);
        $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

        $check = getimagesize($_FILES["profile_picture"]["tmp_name"]);
        if ($check !== false) {
            if (move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $target_file)) {
                $profile_picture = basename($_FILES["profile_picture"]["name"]);
            } else {
                echo "Sorry, there was an error uploading your file.";
                exit();
            }
        } else {
            echo "File is not an image.";
            exit();
        }
    }


    $email_check_sql = "SELECT COUNT(*) FROM users WHERE email = ?";
    $stmt = $conn->prepare($email_check_sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($email_count);
    $stmt->fetch();
    $stmt->close();

    if ($email_count > 0) {
        echo "The email address is already in use. Please use a different email.";
        exit();
    }


    $sql = "INSERT INTO users (username, email, password, profile_picture, membership_tier) VALUES (?, ?, ?, ?, 'Free')";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ssss", $username, $email, $hashed_password, $profile_picture);

    if ($stmt->execute()) {
        echo "
            <html>
            <head>
                <title>Registration Successful</title>
                <style>
                    body {
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background-color: #f7f7f7;
                        overflow: hidden;
                        flex-direction: column;
                        text-align: center;
                    }
                    .message-container {
                        padding: 30px;
                        background-color: #fff;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        z-index: 2;
                        position: relative;
                    }
                    .message-container h1 {
                        font-size: 36px;
                        color: #28a745;
                        animation: congratulation 2s ease-in-out;
                    }
                    @keyframes congratulation {
                        0% { transform: scale(0); opacity: 0; }
                        50% { transform: scale(1.2); opacity: 1; }
                        100% { transform: scale(1); opacity: 1; }
                    }
                    .logo {
                        width: 100px;
                        margin-top: 20px;
                        animation: bounce 1s infinite;
                    }
                    @keyframes bounce {
                        0%, 20%, 50%, 80%, 100% {
                            transform: translateY(0);
                        }
                        40% {
                            transform: translateY(-10px);
                        }
                        60% {
                            transform: translateY(-5px);
                        }
                    }
                    .cta {
                        margin-top: 20px;
                        font-size: 18px;
                    }
                    .cta a {
                        padding: 10px 20px;
                        background-color: #28a745;
                        color: white;
                        text-decoration: none;
                        font-weight: bold;
                        border-radius: 5px;
                        transition: background-color 0.3s;
                    }
                    .cta a:hover {
                        background-color: #218838;
                    }
                    .cta a:active {
                        transform: scale(0.98);
                    }
                </style>
            </head>
            <body>
                <div class='message-container'>
                    <h1>Congratulations! You've Successfully Registered</h1>
                    <img src='momoyo.png' alt='Momoyo' class='logo'>
                    <p class='cta'>You are now a member! <a href='login.php'>Login here</a></p>
                </div>
            </body>
            </html>
        ";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>




