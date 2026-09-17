import secrets
import string

def generate_api_key(prefix="sk_live_", length=32):
    """
    Generates a secure, cryptographically random API key.
    
    :param prefix: Prefix to identify the key type/environment (e.g., 'sk_live_', 'sk_test_')
    :param length: Number of random bytes/characters
    :return: Formatted API key string
    """
    # Generate a cryptographically secure URL-safe random token
    raw_key = secrets.token_urlsafe(length)
    
    # Combine prefix with the generated token
    full_api_key = f"{prefix}{raw_key}"
    return full_api_key

if __name__ == "__main__":
    new_api_key = generate_api_key()
    print("Generated API Key:")
    print(new_api_key)