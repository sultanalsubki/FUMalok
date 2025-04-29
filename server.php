<?php
// Start session
session_start();

// Database connection
function connectDB() {
    try {
        error_log('Connecting to Neon Postgres...');
        $conn = new PDO(
            "pgsql:host=ep-sweet-dust-a2f7jkr0-pooler.eu-central-1.aws.neon.tech;port=5432;dbname=neondb;sslmode=require",
            "neondb_owner",
            "npg_smh8ZFwnO4Yr",
            array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            )
        );
        error_log('Database connection established successfully.');
        return $conn;
    } catch(PDOException $e) {
        error_log('Database connection failed: ' . $e->getMessage());
        return [
            'success' => false,
            'message' => 'Database connection failed: ' . $e->getMessage()
        ];
    }
}

// Response function
function sendResponse($data) {
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// Validate input
function validateInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_email']);
}

// User signup
function signup() {
    if (!isset($_POST['email']) || !isset($_POST['password']) || !isset($_POST['confirm_password'])) {
        return ['success' => false, 'message' => 'All fields are required'];
    }
    
    $email = validateInput($_POST['email']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Invalid email format'];
    }
    if ($password !== $confirmPassword) {
        return ['success' => false, 'message' => 'Passwords do not match'];
    }
    if (strlen($password) < 6) {
        return ['success' => false, 'message' => 'Password must be at least 6 characters long'];
    }
    
    $conn = connectDB();
    if (!is_object($conn)) {
        return $conn;
    }
    
    $sql = 'SELECT "email" FROM "User" WHERE "email" = ?';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $email);
    $stmt->execute();
    $result = $stmt->fetch();
    
    if ($result) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Email already exists'];
    }
    
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $sql = 'INSERT INTO "User" ("email", "password") VALUES (?, ?)';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $email);
    $stmt->bindParam(2, $hashedPassword);
    
    if ($stmt->execute()) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'message' => 'Signup successful'];
    } else {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Error creating account'];
    }
}

// User login
function login() {
    if (!isset($_POST['email']) || !isset($_POST['password'])) {
        return ['success' => false, 'message' => 'Email and password are required'];
    }
    
    $email = validateInput($_POST['email']);
    $password = $_POST['password'];
    
    $conn = connectDB();
    if (!is_object($conn)) {
        return $conn;
    }
    
    $sql = 'SELECT "email", "password" FROM "User" WHERE "email" = ?';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $email);
    $stmt->execute();
    $result = $stmt->fetch();
    
    if ($result && password_verify($password, $result['password'])) {
        $_SESSION['user_email'] = $result['email'];
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'message' => 'Login successful'];
    }
    
    $stmt->closeCursor();
    $conn = null;
    return ['success' => false, 'message' => 'Invalid email or password'];
}

// User logout
function logout() {
    session_unset();
    session_destroy();
    return ['success' => true, 'message' => 'Logout successful'];
}

// Check session
function checkSession() {
    if (isLoggedIn()) {
        return ['success' => true, 'email' => $_SESSION['user_email']];
    } else {
        return ['success' => false, 'message' => 'Not logged in'];
    }
}

// Add task
function addTask() {
    if (!isLoggedIn()) return ['success' => false, 'message' => 'User not logged in'];
    if (!isset($_POST['task_name']) || !isset($_POST['task_date'])) return ['success' => false, 'message' => 'Task name and date are required'];
    
    $taskName = validateInput($_POST['task_name']);
    $taskDate = validateInput($_POST['task_date']);
    $userEmail = $_SESSION['user_email'];
    $status = 'Active';
    
    if (empty($taskName)) return ['success' => false, 'message' => 'Task name cannot be empty'];
    if (!empty($taskDate)) {
        // Try to parse the datetime
        $date = DateTime::createFromFormat('Y-m-d\TH:i', $taskDate);
        if (!$date) {
            return ['success' => false, 'message' => 'Invalid date format. Please use YYYY-MM-DDTHH:MM'];
        }
        $taskDate = $date->format('Y-m-d');
    }
    
    $conn = connectDB();
    if (!is_object($conn)) return $conn;
    
    $stmt = $conn->prepare('INSERT INTO "Task" ("name", "date", "status", "user_email") VALUES (?, ?, ?, ?)');
    $stmt->bindParam(1, $taskName);
    $stmt->bindParam(2, $taskDate);
    $stmt->bindParam(3, $status);
    $stmt->bindParam(4, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'message' => 'Task added successfully'];
    } else {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Error adding task'];
    }
}

// Get tasks
function getTasks() {
    if (!isLoggedIn()) return ['success' => false, 'message' => 'User not logged in'];
    
    $userEmail = $_SESSION['user_email'];
    $conn = connectDB();
    if (!is_object($conn)) return $conn;
    
    $stmt = $conn->prepare('SELECT "id", "name", "date", "status" FROM "Task" WHERE "user_email" = ? ORDER BY "date" ASC');
    $stmt->bindParam(1, $userEmail);
    $stmt->execute();
    $result = $stmt->fetchAll();
    
    $tasks = ['Active' => [], 'Completed' => []];
    foreach ($result as $task) {
        $tasks[$task['status']][] = $task;
    }
    
    $stmt->closeCursor();
    $conn = null;
    return ['success' => true, 'tasks' => $tasks];
}

// Get single task
function getTask() {
    if (!isLoggedIn()) return ['success' => false, 'message' => 'User not logged in'];
    if (!isset($_POST['task_id'])) return ['success' => false, 'message' => 'Task ID is required'];
    
    $taskId = (int)$_POST['task_id'];
    $userEmail = $_SESSION['user_email'];
    
    $conn = connectDB();
    if (!is_object($conn)) return $conn;
    
    $stmt = $conn->prepare('SELECT "id", "name", "date", "status" FROM "Task" WHERE "id" = ? AND "user_email" = ?');
    $stmt->bindParam(1, $taskId);
    $stmt->bindParam(2, $userEmail);
    $stmt->execute();
    $result = $stmt->fetch();
    
    if ($result) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'task' => $result];
    } else {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Task not found'];
    }
}

// Update task
function updateTask() {
    if (!isLoggedIn()) return ['success' => false, 'message' => 'User not logged in'];
    if (!isset($_POST['task_id']) || !isset($_POST['task_name'])) return ['success' => false, 'message' => 'Task ID and name are required'];
    
    $taskId = validateInput($_POST['task_id']);
    $taskName = validateInput($_POST['task_name']);
    $taskDate = isset($_POST['task_date']) ? validateInput($_POST['task_date']) : '';
    $taskStatus = validateInput($_POST['task_status']);
    $userEmail = $_SESSION['user_email'];
    
    if (empty($taskName)) return ['success' => false, 'message' => 'Task name cannot be empty'];
    if ($taskStatus === 'Active' && !empty($taskDate)) {
        // Try to parse the datetime
        $date = DateTime::createFromFormat('Y-m-d\TH:i', $taskDate);
        if (!$date) {
            return ['success' => false, 'message' => 'Invalid date format. Please use YYYY-MM-DDTHH:MM'];
        }
        $taskDate = $date->format('Y-m-d');
    }
    if (!in_array($taskStatus, ['Active', 'Completed'])) return ['success' => false, 'message' => 'Invalid status'];
    
    $conn = connectDB();
    if (!is_object($conn)) return $conn;
    
    $stmt = $conn->prepare('UPDATE "Task" SET "name" = ?, "date" = ?, "status" = ? WHERE "id" = ? AND "user_email" = ?');
    $stmt->bindParam(1, $taskName);
    $stmt->bindParam(2, $taskDate);
    $stmt->bindParam(3, $taskStatus);
    $stmt->bindParam(4, $taskId);
    $stmt->bindParam(5, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'message' => 'Task updated successfully'];
    } else {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Error updating task'];
    }
}

// Delete task
function deleteTask() {
    if (!isLoggedIn()) return ['success' => false, 'message' => 'User not logged in'];
    if (!isset($_POST['task_id'])) return ['success' => false, 'message' => 'Task ID is required'];
    
    $taskId = (int)$_POST['task_id'];
    $userEmail = $_SESSION['user_email'];
    
    $conn = connectDB();
    if (!is_object($conn)) return $conn;
    
    $stmt = $conn->prepare('DELETE FROM "Task" WHERE "id" = ? AND "user_email" = ?');
    $stmt->bindParam(1, $taskId);
    $stmt->bindParam(2, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => true, 'message' => 'Task deleted successfully'];
    } else {
        $stmt->closeCursor();
        $conn = null;
        return ['success' => false, 'message' => 'Error deleting task'];
    }
}

// Main handler
$action = $_POST['action'] ?? '';
$response = [];

switch ($action) {
    case 'signup': $response = signup(); break;
    case 'login': $response = login(); break;
    case 'logout': $response = logout(); break;
    case 'check_session': $response = checkSession(); break;
    case 'add_task': $response = addTask(); break;
    case 'get_tasks': $response = getTasks(); break;
    case 'get_task': $response = getTask(); break;
    case 'update_task': $response = updateTask(); break;
    case 'delete_task': $response = deleteTask(); break;
    default: $response = ['success' => false, 'message' => 'Invalid action'];
}

sendResponse($response);
?>