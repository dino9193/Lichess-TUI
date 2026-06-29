from pathlib import Path # Hệ thống đường chuẩn XDG
import json # Lưu trữ dữ liệu dưới dạng json
import os # Giao tiếp với hệ điều hành
import base64 # Lưu trữ salt an toàn
import berserk # Giao tiếp với Lichess

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

	def validate_token (self, token:str) :
		# Kiểm tra sự tồn tại của token
		try :
			session = berserk.TokenSession(token)
			client = berserk.Client(session)
			client.account.get()
			return True
		except berserk.exceptions.ResponseError :
			return False
	
	def _derive_key(self, passphrase:str, salt:bytes):
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
	
	def save_token(self, username:str, passphrase:str, token:str) :
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
	
	def load_token (self, username:str, passphrase:str) :
		if self.config_file.exists() :
			with open (self.config_file, "r", encoding="utf-8") as f :
				all_accounts = json.load(f)
			key = self._derive_key(passphrase, all_accounts[username]["salt"])
			f = Fernet(key)
			try :
				decrypted_bytes = f.decrypt(all_accounts[username]["token"])
				return decrypted_bytes.decode("utf-8")
			except InvalidToken:
				return "Passphrase wrong"
		else :
			return None

if __name__ == "__main__" :
	import sys

	print ("Đang chạy test Auth độc lập!!")

	username = input ("Đặt tên cho tài khoản test: ")
	token_lichess = input ("Đặt token thử nghiệm (có hoạt động): ")
	passphrase = input ("Đặt passphrase thử nghiệm: ")

	auth = LichessAuth()

	print("Đang kiểm tra sự tồn tại của token")
	if auth.validate_token(token_lichess) :
		print("Token có tồn tại!")
	else :
		sys.exit("Token không tồn tại")

	print ("Đang kiểm tra check_user.")
	if auth.check_account() is None :
		print ("Tính năng check_account ổn!")
	else :
		sys.exit("Tính năng chạy không ổn hoặc đã có file trên hệ thống hãy kiểm tra lại!")

	print("Đang kiểm tra tính năng save_token")
	if auth.save_token(username, passphrase, token_lichess) == "Invalid token" :
		sys.exit("Kiểm tra lại berserk")
	else :
		print("Tính năng save_token ổn!")

	print("Đang kiểm tra tính năng check_account")
	all_accounts = auth.check_account()
	if all_accounts is not None :
		print(f"Tính năng check_account hoạt động ổn, danh sách các tài khoản là : {all_accounts}")
	else :
		print("Tính năng check_account hoạt động không ổn hoặc tính năng save_token hoạt động không ổn")
	
	print("Đang kiểm tra tính năng load_token")
	token = auth.load_token(username, passphrase)
	if token is not None :
		if token == token_lichess :
			print("Tính năng load_token hoạt động ổn!")
		else :
			print("Tính năng load_token hoạt động không ổn!")
	else :
		print("Tính năng save_token hoạt động không ổn")
	
	print("Đang dọn dẹp sau khi test!")
	if auth.config_file.exists() :
		auth.config_file.unlink()
		print("Đã xóa thành công!")
	else :
		print("File config không tồn tại!")