/* Toggle Theme (Dark/Light) */
function toggleTheme() {
    const body = document.body;
    body.classList.toggle('dark-theme');
    
    // Save the theme preference to localStorage
    if (body.classList.contains('dark-theme')) {
        localStorage.setItem('theme', 'dark');
    } else {
        localStorage.setItem('theme', 'light');
    }
}

/* Set Initial Theme on Page Load */
function setInitialTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
    }
}

/* Show Alert when a Form is Submitted */
function showAlert(message) {
    alert(message);
}

/* Decrypt Password (for view password page) */
function decryptPassword() {
    const encryptedPassword = document.getElementById('encryptedPassword');
    const decryptedPassword = document.getElementById('decryptedPassword');

    // Example: Base64 decoding (replace with actual decryption logic)
    decryptedPassword.textContent = atob(encryptedPassword.textContent);
}

/* Wait for the page to load and apply saved theme */
window.onload = function () {
    setInitialTheme();
};

// Optional: Call theme toggle function from a button
document.getElementById('themeToggleBtn')?.addEventListener('click', toggleTheme);
