<?php

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = htmlspecialchars($_POST["username"]);
    $password = $_POST["password"];

    if (empty($username) || empty($password)) {
        header("Location: login.html?error=emptyfields");
        exit();
    }

    try {
        require_once 'Tokadatabasehandler.php';
        $query = "SELECT user_password FROM customer_account WHERE username = :username OR email = :username;";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && password_verify($password, $result['user_password'])) {
            // Login successful, redirect to dieting page
            header("Location: ../index.html");
            exit();
        } else {
            header("Location: login.html?error=invalidcredentials");
            exit();
        }
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
} else {
    header("Location: ../index.html");
    exit();
}
?>