<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database connection
try {
    echo "Connecting to database...<br>";
    
    $conn = new PDO(
        "pgsql:host=ep-sweet-dust-a2f7jkr0-pooler.eu-central-1.aws.neon.tech;port=5432;dbname=neondb;sslmode=require",
        "neondb_owner",
        "npg_smh8ZFwnO4Yr",
        array(
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        )
    );
    
    echo "Database connection successful!<br><br>";
    
    // Check if User table exists
    $stmt = $conn->prepare("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'User')");
    $stmt->execute();
    $tableExists = $stmt->fetch()["exists"];
    
    if ($tableExists) {
        echo "User table exists.<br><br>";
        
        // List all columns in User table
        $stmt = $conn->prepare("SELECT column_name FROM information_schema.columns WHERE table_name = 'User'");
        $stmt->execute();
        $columns = $stmt->fetchAll();
        
        echo "Columns in User table:<br>";
        foreach ($columns as $column) {
            echo "- " . $column["column_name"] . "<br>";
        }
        echo "<br>";
        
        // Try a simple query
        echo "Testing SELECT query...<br>";
        $stmt = $conn->prepare("SELECT * FROM User LIMIT 1");
        $stmt->execute();
        $result = $stmt->fetch();
        
        if ($result) {
            echo "Found a user record:<br>";
            print_r($result);
        } else {
            echo "No user records found.<br>";
        }
        
    } else {
        echo "User table does not exist.<br>";
        
        // Try to create the table
        echo "Attempting to create User table...<br>";
        $sql = "CREATE TABLE User (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        
        try {
            $conn->exec($sql);
            echo "User table created successfully!<br>";
        } catch(PDOException $e) {
            echo "Error creating User table: " . $e->getMessage() . "<br>";
        }
    }
    
} catch(PDOException $e) {
    echo "Connection failed: " . $e->getMessage() . "<br>";
}

?>
