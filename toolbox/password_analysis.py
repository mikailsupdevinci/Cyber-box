def analyze_password_strength(passwords):
    weak_passwords = [pwd for pwd in passwords if len(pwd) < 8]
    print(f"Weak passwords: {weak_passwords}")
    return weak_passwords
