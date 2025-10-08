const emailInput = document.getElementById('email');
const emailMsg = document.getElementById('emailMsg');
const registerBtn = document.getElementById('registerBtn');

const passwordInput = document.getElementById('password');
const confirmInput = document.getElementById('confirm_password');
const passwordMsg = document.getElementById('passwordMsg');

emailInput.addEventListener('input', async () => {
    const email = emailInput.value;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;

    if (!emailRegex.test(email)) {
        emailMsg.textContent = "⚠️ 請輸入有效的 Gmail";
        emailMsg.style.color = "red";
        registerBtn.disabled = true;
        return;
    }

    const res = await fetch('/check_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
    });
    const data = await res.json();

    if (data.exists) {
        emailMsg.textContent = "⚠️ 此電子郵件已被註冊";
        emailMsg.style.color = "red";
        registerBtn.disabled = true;
    } else {
        emailMsg.textContent = "✅ 可以使用";
        emailMsg.style.color = "green";
        registerBtn.disabled = false;
    }
});

function checkPasswordMatch() {
    if (passwordInput.value && confirmInput.value) {
        if (passwordInput.value !== confirmInput.value) {
            passwordMsg.textContent = "⚠️ 密碼不一致";
            passwordMsg.style.color = "red";
            registerBtn.disabled = true;
        } else {
            passwordMsg.textContent = "✅ 密碼一致";
            passwordMsg.style.color = "green";
            registerBtn.disabled = false;
        }
    } else {
        passwordMsg.textContent = "";
    }
}

passwordInput.addEventListener('input', checkPasswordMatch);
confirmInput.addEventListener('input', checkPasswordMatch);
