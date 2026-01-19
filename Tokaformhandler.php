<?php 

if($_SERVER["REQUEST_METHOD"] == "POST") {
    
    // Process form data
    $Username = htmlspecialchars($_POST["Username"]);
    if(empty($Username)) {
        header("Location: ../Register.html?error=emptyusername");
        exit();
    }
    $Email = htmlspecialchars($_POST["email"]);
    if(empty($Email)) {
        header("Location: ../Register.html?error=emptyemail");
        exit();
    }
    $Password = htmlspecialchars($_POST["password"]);
    if(empty($Password)) {
        header("Location: ../Register.html?error=emptypassword");
        exit();
    }
    $Age = $_POST["age"];
    if(empty($Age)) {
        header("Location: ../Register.html?error=emptyage");
        exit();
    }
    $sName = htmlspecialchars($_POST["sName"]);
    if(empty($sName)) {
        header("Location: ../Register.html?error=emptysurname");
        exit();
    }
    $fName = htmlspecialchars($_POST["fName"]);
    if(empty($fName)) {
        header("Location: ../Register.html?error=emptyfirstname");
        exit();
    }


    $PasswordOptions = [
        'cost' => 12,
    ];
    $hashPwd = password_hash($Password, PASSWORD_BCRYPT, $PasswordOptions);


    try{
        require_once 'Tokadatabasehandler.php';
        $query = "INSERT INTO customer_account (username, user_password, email, user_age, first_name, surname) VALUES (:Username, :Password, :Email, :Age, :fName, :sName);";
        $stmt = $pdo->prepare($query);
        $stmt->bindParam(':Username', $Username);
        $stmt->bindParam(':Email', $Email);
        $stmt->bindParam(':Password', $hashPwd);
        $stmt->bindParam(':Age', $Age);
        $stmt->bindParam(':fName', $fName);
        $stmt->bindParam(':sName', $sName);
        $stmt->execute();
        $stmt = null;
        $pdo = null;
        header("Location: Index.html");
        die();

    } catch (PDOException $e){
        die("Could not connect to the database:" . $e->getMessage());
    }



} else {
    // Handle non-POST requests
    header("Location: Index.html");
}