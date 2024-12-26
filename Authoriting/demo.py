import jwt
from datetime import datetime, timedelta, timezone

# Secret key for encoding/decoding
SECRET_KEY = "your_secret_key"

# Function to create a JWT token
def create_token(data):
    # Use timezone-aware UTC datetime
    return jwt.encode(
        {"data": data, "exp": datetime.now(timezone.utc) + timedelta(minutes=15)},
        SECRET_KEY,
        algorithm="HS256",
    )

# Function to decode a JWT token
def decode_token(encoded_token):
    try:
        return jwt.decode(encoded_token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return "Token has expired"
    except jwt.InvalidTokenError:
        return "Invalid token"

if __name__ == "__main__":
    # Create a token
    token = create_token({"user_id": 123})
    print("Generated Token:", token)

    # Decode the token
    decoded = decode_token(token)
    print("Decoded Token:", decoded)
