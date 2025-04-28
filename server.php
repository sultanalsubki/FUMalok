<?php
// Start session
session_start();

// Database connection
function connectDB() {
    $host = 'localhost';
    $username = 'root';
    $password = '';
    $database = 'task_manager';
    
    $conn = new mysqli($host, $username, $password, $database);
    
    if ($conn->connect_error) {
        return [
            'success' => false,
            'message' => 'Database connection failed: ' . $conn->connect_error
        ];
    }
    
    return $conn;
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
        return [
            'success' => false,
            'message' => 'All fields are required'
        ];
    }
    
    $email = validateInput($_POST['email']);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];
    
    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return [
            'success' => false,
            'message' => 'Invalid email format'
        ];
    }
    
    // Check if passwords match
    if ($password !== $confirmPassword) {
        return [
            'success' => false,
            'message' => 'Passwords do not match'
        ];
    }
    
    // Check password length
    if (strlen($password) < 6) {
        return [
            'success' => false,
            'message' => 'Password must be at least 6 characters long'
        ];
    }
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Check if email already exists
    $stmt = $conn->prepare("SELECT email FROM User WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $stmt->close();
        $conn->close();
        return [
            'success' => false,
            'message' => 'Email already exists'
        ];
    }
    
    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert new user
    $stmt = $conn->prepare("INSERT INTO User (email, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $email, $hashedPassword);
    
    if ($stmt->execute()) {
        $stmt->close();
        $conn->close();
        return [
            'success' => true,
            'message' => 'Signup successful'
        ];
    } else {
        $stmt->close();
        $conn->close();
        return [
            'success' => false,
            'message' => 'Error creating account: ' . $conn->error
        ];
    }
}

// User login
function login() {
    if (!isset($_POST['email']) || !isset($_POST['password'])) {
        return [
            'success' => false,
            'message' => 'Email and password are required'
        ];
    }
    
    $email = validateInput($_POST['email']);
    $password = $_POST['password'];
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Get user from database
    $stmt = $conn->prepare("SELECT email, password FROM User WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        
        // Verify password
        if (password_verify($password, $user['password'])) {
            // Set session
            $_SESSION['user_email'] = $user['email'];
            
            $stmt->close();
            $conn->close();
            return [
                'success' => true,
                'message' => 'Login successful'
            ];
        }
    }
    
    $stmt->close();
    $conn->close();
    return [
        'success' => false,
        'message' => 'Invalid email or password'
    ];
}

// User logout
function logout() {
    // Destroy session
    session_unset();
    session_destroy();
    
    return [
        'success' => true,
        'message' => 'Logout successful'
    ];
}

// Check session
function checkSession() {
    if (isLoggedIn()) {
        return [
            'success' => true,
            'email' => $_SESSION['user_email']
        ];
    } else {
        return [
            'success' => false,
            'message' => 'Not logged in'
        ];
    }
}

// Add task
function addTask() {
    if (!isLoggedIn()) {
        return [
            'success' => false,
            'message' => 'User not logged in'
        ];
    }
    
    if (!isset($_POST['task_name']) || !isset($_POST['task_date'])) {
        return [
            'success' => false,
            'message' => 'Task name and date are required'
        ];
    }
    
    $taskName = validateInput($_POST['task_name']);
    $taskDate = validateInput($_POST['task_date']);
    $userEmail = $_SESSION['user_email'];
    $status = 'Active'; // Default status
    
    // Validate task name
    if (empty($taskName)) {
        return [
            'success' => false,
            'message' => 'Task name cannot be empty'
        ];
    }
    
    // Validate date format
    if (!preg_match("/^\d{4}-\d{2}-\d{2}$/", $taskDate)) {
        return [
            'success' => false,
            'message' => 'Invalid date format'
        ];
    }
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Insert task
    $stmt = $conn->prepare("INSERT INTO Task (Name, Date, Status, user_email) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $taskName, $taskDate, $status, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->close();
        $conn->close();
        return [
            'success' => true,
            'message' => 'Task added successfully'
        ];
    } else {
        $stmt->close();
        $conn->close();
        return [
            'success' => false,
            'message' => 'Error adding task: ' . $conn->error
        ];
    }
}

// Get tasks
function getTasks() {
    if (!isLoggedIn()) {
        return [
            'success' => false,
            'message' => 'User not logged in'
        ];
    }
    
    $userEmail = $_SESSION['user_email'];
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Get tasks grouped by status
    $stmt = $conn->prepare("SELECT id, Name, Date, Status FROM Task WHERE user_email = ? ORDER BY Date ASC");
    $stmt->bind_param("s", $userEmail);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $tasks = [
        'Active' => [],
        'Completed' => []
    ];
    
    while ($task = $result->fetch_assoc()) {
        $tasks[$task['Status']][] = $task;
    }
    
    $stmt->close();
    $conn->close();
    
    return [
        'success' => true,
        'tasks' => $tasks
    ];
}

// Get single task
function getTask() {
    if (!isLoggedIn()) {
        return [
            'success' => false,
            'message' => 'User not logged in'
        ];
    }
    
    if (!isset($_POST['task_id'])) {
        return [
            'success' => false,
            'message' => 'Task ID is required'
        ];
    }
    
    $taskId = (int)$_POST['task_id'];
    $userEmail = $_SESSION['user_email'];
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Get task
    $stmt = $conn->prepare("SELECT id, Name, Date, Status FROM Task WHERE id = ? AND user_email = ?");
    $stmt->bind_param("is", $taskId, $userEmail);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $task = $result->fetch_assoc();
        
        $stmt->close();
        $conn->close();
        
        return [
            'success' => true,
            'task' => $task
        ];
    } else {
        $stmt->close();
        $conn->close();
        
        return [
            'success' => false,
            'message' => 'Task not found'
        ];
    }
}

// Update task
function updateTask() {
    if (!isLoggedIn()) {
        return [
            'success' => false,
            'message' => 'User not logged in'
        ];
    }
    
    if (!isset($_POST['task_id']) || !isset($_POST['task_name']) || !isset($_POST['task_date']) || !isset($_POST['task_status'])) {
        return [
            'success' => false,
            'message' => 'All fields are required'
        ];
    }
    
    $taskId = (int)$_POST['task_id'];
    $taskName = validateInput($_POST['task_name']);
    $taskDate = validateInput($_POST['task_date']);
    $taskStatus = validateInput($_POST['task_status']);
    $userEmail = $_SESSION['user_email'];
    
    // Validate task name
    if (empty($taskName)) {
        return [
            'success' => false,
            'message' => 'Task name cannot be empty'
        ];
    }
    
    // Validate date format
    if (!preg_match("/^\d{4}-\d{2}-\d{2}$/", $taskDate)) {
        return [
            'success' => false,
            'message' => 'Invalid date format'
        ];
    }
    
    // Validate status
    if ($taskStatus !== 'Active' && $taskStatus !== 'Completed') {
        return [
            'success' => false,
            'message' => 'Invalid status'
        ];
    }
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Update task
    $stmt = $conn->prepare("UPDATE Task SET Name = ?, Date = ?, Status = ? WHERE id = ? AND user_email = ?");
    $stmt->bind_param("sssis", $taskName, $taskDate, $taskStatus, $taskId, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->close();
        $conn->close();
        
        return [
            'success' => true,
            'message' => 'Task updated successfully'
        ];
    } else {
        $stmt->close();
        $conn->close();
        
        return [
            'success' => false,
            'message' => 'Error updating task: ' . $conn->error
        ];
    }
}

// Delete task
function deleteTask() {
    if (!isLoggedIn()) {
        return [
            'success' => false,
            'message' => 'User not logged in'
        ];
    }
    
    if (!isset($_POST['task_id'])) {
        return [
            'success' => false,
            'message' => 'Task ID is required'
        ];
    }
    
    $taskId = (int)$_POST['task_id'];
    $userEmail = $_SESSION['user_email'];
    
    $conn = connectDB();
    
    if (!is_object($conn)) {
        return $conn; // Return error from connectDB
    }
    
    // Delete task
    $stmt = $conn->prepare("DELETE FROM Task WHERE id = ? AND user_email = ?");
    $stmt->bind_param("is", $taskId, $userEmail);
    
    if ($stmt->execute()) {
        $stmt->close();
        $conn->close();
        
        return [
            'success' => true,
            'message' => 'Task deleted successfully'
        ];
    } else {
        $stmt->close();
        $conn->close();
        
        return [
            'success' => false,
            'message' => 'Error deleting task: ' . $conn->error
        ];
    }
}

// Main handler
$action = isset($_POST['action']) ? $_POST['action'] : '';
$response = [];

switch ($action) {
    case 'signup':
        $response = signup();
        break;
    case 'login':
        $response = login();
        break;
    case 'logout':
        $response = logout();
        break;
    case 'check_session':
        $response = checkSession();
        break;
    case 'add_task':
        $response = addTask();
        break;
    case 'get_tasks':
        $response = getTasks();
        break;
    case 'get_task':
        $response = getTask();
        break;
    case 'update_task':
        $response = updateTask();
        break;
    case 'delete_task':
        $response = deleteTask();
        break;
    default:
        $response = [
            'success' => false,
            'message' => 'Invalid action'
        ];
}

sendResponse($response);
?>
