<?php
//The datasource name, or DSN, contains the information required to connect to the database. 
//Two values are required: the name of the driver and the name of the database.
 $dsn = "mysql:host=localhost;dbname=tokadatabase";
 //Store default username and password for localhost
 $dbusername = "root";
 $dbpassword = "";

 // A try and catch block to catch any errors connecting to the database.
 //This is good practice for stability and security
 try {
     //Create a PDO instance (connect to the database), PDO is PHP Data Objects. 
     //Take the above information, the $dsn, $username and $password. Use these to connect to the database
     //new PDO is the constructor that creates the PDO object
     $pdo = new PDO($dsn, $dbusername, $dbpassword);
     //Set Error Mode and messages to Exception, if there is an error, an exception will be thrown
     $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
 } catch (PDOException $e) {
     //If there is an error in the connection, we will get the error message, error instance known as $e
     echo "Connection failed: " . $e->getMessage();
 }
