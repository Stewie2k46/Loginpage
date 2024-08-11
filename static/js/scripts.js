document.getElementById('registerForm').addEventListener('submit', function(event) {
    event.preventDefault();
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    localStorage.setItem('username', username);
    localStorage.setItem('password', password);

    alert('Registration successful! Redirecting to login page.');
    window.location.href = "/login";
});

document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    let storedUsername = localStorage.getItem('username');
    let storedPassword = localStorage.getItem('password');

    if (username === storedUsername && password === storedPassword) {
        alert('Login successful!');
        // Redirect to the home page or dashboard
        // window.location.href = "/home";
    } else {
        alert('Incorrect username or password!');
    }
});
