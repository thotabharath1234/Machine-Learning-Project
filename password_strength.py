import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
import warnings


def extract_features(password):
    features = {}
    features['length'] = len(password)
    features['uppercase_count'] = sum(1 for c in password if c.isupper())
    features['lowercase_count'] = sum(1 for c in password if c.islower())
    features['digit_count'] = sum(1 for c in password if c.isdigit())
    features['special_char_count'] = sum(1 for c in password if re.match(r'[!@#$%^&*()\-_=+{};:,<.>]', c))
    return features

data = [
    ('P@ssw0rd', 1),
    ('Weak123', 0),
    ('Strong123', 1),
    ('12345678', 0),
    ('AbCdEfGh', 0),
    ('SecurePwd!2022', 1),
    ('MyP@ssword123', 1),
    ('qwerty12345', 0),
    ('NewYear2023!', 1),
    ('abcdefgh', 0),
    ('Secret#2023', 1),
    ('Passw0rd!', 1),
    ('SecureLogin2022', 1),
    ('SuperSecret123!', 1),
    ('Admin@123', 1),
    ('User1234', 0),
    ('MySecureData2023!', 1),
    ('Password12345', 0),
    ('StrongP@ss123', 1),
    ('WeakPass', 0),
    ('AnotherSecret!2022', 1),
    ('1234abcd', 0),
    ('Secure123!', 1),
    ('Login123', 0),
    ('Safe&Secure2023', 1),
    ('P@$$w0rd!', 1),
    ('SimplePwd', 0),
    ('1234567', 0),
    ('Complex&Safe!2022', 1),
    ('Password!123', 0),
    ('Unbreakable2023!', 1),
]


df = pd.DataFrame(data, columns=['Password', 'Strength'])

df['Features'] = df['Password'].apply(extract_features)
feature_columns = ['length', 'uppercase_count', 'lowercase_count', 'digit_count', 'special_char_count']

X = df['Features'].apply(lambda x: [x[feature] for feature in feature_columns])
X = pd.DataFrame(X.tolist(), columns=feature_columns)

y = df['Strength']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

warnings.filterwarnings("ignore")
model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)


def is_strong_password_ml(username, password):
    if len(password) < 8:
        return False  # Password should be at least 8 characters long

    if not any(c.isupper() for c in password):
        return False  # Password should have at least one uppercase letter

    if not any(c.islower() for c in password):
        return False  # Password should have at least one lowercase letter

    if not any(c.isdigit() for c in password):
        return False  # Password should have at least one digit

    if not any(re.match(r'[!@#$%^&*()\-_=+{};:,<.>]', c) for c in password):
        return False  # Password should have at least one special character

    if ' ' in password:
        return False  # Password should not contain spaces

    if username in password:
        print("Password should not contain the username as a part of it.")
        return False  # Password should not contain the username

    return True


while True:
    print("Criteria for a strong password")
    print(
        "\tAt least 8 characters\n\tAt least one uppercase letter\n\tAt least one lowercase letter\n\tAt least one digit\n\tAt least one special character")
    print("\tNo spaces allowed")
    print("\tPassword should not contain the username as a part of it\n")

    username = input("Enter your Username: ")
    password = input("Enter a Password: ")

    print("\n")

    if ' ' in password:
        print("Password should not contain spaces. Please try again.\n")
        continue

    if username == password:
        print("Username and password cannot be the same. Please try again.\n")
        continue

    if is_strong_password_ml(username, password):
        print("Strong password! You can proceed with your registration.\n")
        break
    else:
        print("Weak password. Please choose a stronger password.\n")
