from pathlib import Path # Hệ thống đường chuẩn XDG
import json # Lưu trữ dữ liệu dưới dạng json
import os # Giao tiếp với hệ điều hành
import base64 # Lưu trữ salt an toàn
import berserk

# Mã hóa token
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class LichessAuth :
	def __init__(self):
		# Tìm vị trí thư mục config
		self.config_dir = Path.home() / ".config" / "Lichess-TUI" 
		self.config_file = self.config_dir / "token.json"
		self.config_dir.mkdir(parents=True, exist_ok=True)

	def validate_token (self, token) :
		# Kiểm tra sự tồn tại của token
		try :
			session = berserk.TokenSession(token)
			client = berserk.Client(session)
			client.account.get()
			return True
		except berserk.exceptions.ResponseError :
			return False
	
	def _derive_key(self, passphrase, salt):
		# Sinh khóa từ passphrase
		if isinstance(passphrase, str):
			passphrase_bytes = passphrase.encode()
		else :
			passphrase_bytes = passphrase
		
		if isinstance(salt, str):
			salt_bytes = base64.b64decode(salt.encode('utf-8'))
		else :
			salt_bytes = salt

		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt_bytes,
			iterations=100000,
		)

		key_goc = kdf.derive(passphrase_bytes)

		return base64.urlsafe_b64encode(key_goc)
	
	def save_token(self, username, passphrase, token) :
		# Lưu token được mã hóa
		if self.validate_token(token) :
			salt = os.urandom(16)
			key = self._derive_key(passphrase, salt)
			f = Fernet(key)
			encrypted_token = f.encrypt(token.encode())

			salt_str = base64.b64encode(salt).decode('utf-8')
			token_str = encrypted_token.decode('utf-8')
			
			if self.config_file.exists() :
				with open (self.config_file, "r", encoding="utf-8") as f :
					all_accounts = json.load(f)
			else :
				all_accounts = {}
			
			all_accounts[username] = {"salt": salt_str, "token": token_str}
			
			with open (self.config_file, "w", encoding="utf-8") as f :
				json.dump(all_accounts, f, indent=4)
		
		else :
			return "Invalid token"
	
	def check_account(self) :
		if self.config_file.exists() :
			with open (self.config_file, "r", encoding="utf-8") as f :
				all_accounts = json.load(f)
			return list(all_accounts.keys())
		else :
			return None
	
	def load_token (self, username, passphrase) :
		if self.config_file.exists() :
			with open (self.config_file, "r", encoding="utf-8") as f :
				all_accounts = json.load(f)
			key = self._derive_key(passphrase, all_accounts[username]["salt"].encode())
			f = Fernet(key)
			try :
				decrypted_bytes = f.decrypt(all_accounts[username]["token"])
				return decrypted_bytes.decode("utf-8")
			except InvalidToken:
				return "Passphare wrong"
		else :
			return None