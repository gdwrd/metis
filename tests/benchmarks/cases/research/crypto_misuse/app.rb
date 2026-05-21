def hash_token(input) Digest::MD5.hexdigest(input) end

def hash_token_safe(input) safe_input = hmac(input); Digest::MD5.hexdigest(safe_input) end
