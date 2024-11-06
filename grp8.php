<?php
session_start();
require_once 'db_connection.php'; // Include the database connection

// Remember me cookie parameters
$cookie_name = "remember_me_token";
$cookie_expiry = time() + (86400 * 30); // 30 days

// Handle AJAX register and login form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $response = ['status' => 'error', 'message' => 'Invalid request'];

    // Handle registration
    if ($_POST['action'] === 'register') {
        $username = filter_var($_POST['username'] ?? '', FILTER_SANITIZE_EMAIL);
        $password = filter_var($_POST['password'] ?? '', FILTER_SANITIZE_SPECIAL_CHARS);

        // Validate that the username ends with "@gmail.com"
        if (substr($username, -10) !== '@gmail.com') {
            $response['message'] = "Username must end with '@gmail.com'.";
        } elseif (strlen($password) < 5 || strlen($password) > 10) {
            $response['message'] = "Password must be between 5 and 10 characters long.";
        } else {
            // Check if username exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);

            if ($stmt->rowCount() > 0) {
                $response['message'] = "Username is already taken.";
            } else {
                // Insert new user
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                if ($stmt->execute([$username, $hashed_password])) {
                    $response = ['status' => 'success', 'message' => "Registration successful! You can now log in."];
                } else {
                    $response['message'] = "Registration failed. Please try again.";
                }
            }
        }
    }

    // Handle login
    if ($_POST['action'] === 'login') {
        $username = filter_var($_POST['username'] ?? '', FILTER_SANITIZE_EMAIL);
        $password = filter_var($_POST['password'] ?? '', FILTER_SANITIZE_SPECIAL_CHARS);
        $remember_me = isset($_POST['remember_me']) ? $_POST['remember_me'] : false;

        // Fetch user from database
        $stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['loggedin'] = true;
            $_SESSION['username'] = htmlspecialchars($username);

            // Set a remember me cookie if selected
            if ($remember_me) {
                $token = bin2hex(random_bytes(16));
                setcookie($cookie_name, $token, $cookie_expiry, "/", "", true, true);
                $stmt = $pdo->prepare("UPDATE users SET remember_token = ? WHERE username = ?");
                $stmt->execute([$token, $username]);
            }

            $response = ['status' => 'success', 'message' => 'Login successful!'];
        } else {
            $response['message'] = "Invalid username or password.";
        }
    }

    // Handle username suggestions
    if ($_POST['action'] === 'suggest') {
        $input = filter_var($_POST['username'] ?? '', FILTER_SANITIZE_EMAIL);
        $suggestions = [];

        $stmt = $pdo->prepare("SELECT username FROM users WHERE username LIKE ?");
        $stmt->execute([$input . '%']);

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $suggestions[] = $row['username'];
        }

        header('Content-Type: application/json');
        echo json_encode(['status' => 'success', 'suggestions' => $suggestions]);
        exit;
    }

    // Send JSON response for login and registration
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    setcookie($cookie_name, "", time() - 3600, "/");
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Automatic login with remember me cookie
if (!isset($_SESSION['loggedin']) && isset($_COOKIE[$cookie_name])) {
    $token = $_COOKIE[$cookie_name];
    $stmt = $pdo->prepare("SELECT username FROM users WHERE remember_token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = htmlspecialchars($user['username']);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login and Registration Form</title>
    <link rel="stylesheet" type="text/css" href="style.css"> <!-- Link to the CSS -->
    
    <!-- jQuery CDN -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>

    <script>
    $(document).ready(function () {
        // Handle login form submission via AJAX
        $('#login-form').on('submit', function (e) {
            e.preventDefault(); // Prevent traditional form submission
            
            // Send AJAX request for login
            $.ajax({
                type: 'POST',
                url: '', // The same page
                data: $(this).serialize(), // Serialize form data
                success: function (response) {
                    if (response.status === 'success') {
                        window.location.reload(); // Reload the page on successful login
                    } else {
                        $('#login-message').removeClass('success').addClass('error').text(response.message);
                    }
                },
                error: function () {
                    $('#login-message').removeClass('success').addClass('error').text('An error occurred.');
                }
            });
        });

        // Handle register form submission via AJAX
        $('#register-form').on('submit', function (e) {
            e.preventDefault(); // Prevent traditional form submission
            
            // Send AJAX request for registration
            $.ajax({
                type: 'POST',
                url: '', // The same page
                data: $(this).serialize(), // Serialize form data
                success: function (response) {
                    if (response.status === 'success') {
                        $('#register-message').removeClass('error').addClass('success').text(response.message);
                        // Clear input fields after submit
                        $('#register_username').val(''); // Clear the username input
                        $('#register_password').val(''); // Clear the password input
                        $('#login_suggestions').empty(); // Clear any login suggestions
                    } else {
                        $('#register-message').removeClass('success').addClass('error').text(response.message);
                    }
                },
                error: function () {
                    $('#register-message').removeClass('success').addClass('error').text('An error occurred.');
                }
            });
        });

        // Handle username input for login suggestions
        $('#username').on('input', function () {
            const input = $(this).val();
            if (input.length > 0) {
                // Send AJAX request for suggestions
                $.ajax({
                    type: 'POST',
                    url: '', // The same page
                    data: {
                        action: 'suggest',
                        username: input
                    },
                    success: function (response) {
                        if (response.status === 'success') {
                            // Display suggestions
                            $('#login_suggestions').empty();
                            if (response.suggestions.length > 0) {
                                response.suggestions.forEach(function (username) {
                                    $('#login_suggestions').append('<li class="suggestion-item" style="cursor: pointer;">' + username + '</li>');
                                });
                            } else {
                                $('#login_suggestions').append('<li>No suggestions available</li>');
                            }
                        }
                    }
                });
            } else {
                // Clear suggestions if input is empty
                $('#login_suggestions').empty();
            }
        });

        // Handle click on suggestion for login
        $(document).on('click', '#login_suggestions .suggestion-item', function () {
            const selectedUsername = $(this).text();
            $('#username').val(selectedUsername); // Set the input value to the selected username
            $('#login_suggestions').empty(); // Clear the suggestions
        });
    });
    </script>
</head>
<body style="background: url('Beezzz.jpg.webp'); background-size: cover; background-position: center; font-family: Arial, sans-serif; text-align: center; background-color: #f4f4f4; align-items: center;">

    <div style="background-color:#ebcb65; border-radius: 15px; padding: 30px; width: 355px; margin: 50px auto; box-shadow: 0 0 15px rgba(0, 0, 0, 0.1); border: 5px solid #df944f;">

<?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin']): ?>
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 50vh;">
        <h1 style="text-align: center;">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
        <p style="text-align: center;">You are now logged in to our homepage.</p>
        <div style="margin-top: 10px; display: flex; flex-direction: row; gap: 10px;">
            <a href="homeprofile.php" style="text-decoration: none; background-color: #df944f; color: white; padding: 10px 15px; border-radius: 5px;">Home Profile</a>
            <a href="?logout=true" style="text-decoration: none; background-color: #df944f; color: white; padding: 10px 15px; border-radius: 5px;">Logout</a>
        </div>
    </div>
<?php else: ?>
        <h2 style="text-align: center;">Login Form</h2>

        <!-- Display login error/success message -->
        <p id="login-message" class="error"></p>

        <!-- Login form -->
        <form id="login-form">
            <input type="hidden" name="action" value="login">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <ul id="login_suggestions" style="list-style: none; padding: 0; margin: 0; text-align: left;"></ul><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>

        <h2 style="text-align: center;">Register Form</h2>

        <!-- Display register error/success message -->
        <p id="register-message" class="error"></p>

        <!-- Register form -->
        <form id="register-form">
            <input type="hidden" name="action" value="register">
            <label for="register_username">Username:</label>
            <input type="text" id="register_username" name="username" required><br>
            <label for="register_password">Password:</label>
            <input type="password" id="register_password" name="password" required><br>
            <button type="submit">Register</button>
        </form>
<?php endif; ?>
    </div>

    <!-- Footer -->
    <footer style="background-color: #333; color: white; padding: 10px; text-align: center; position: absolute; bottom: 0; width: 100%;">
        <p>&copy; 2024 Group_8/Exercise-6. All rights reserved.</p>
    </footer>

</body>
</html>
