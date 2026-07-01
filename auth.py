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
		if isinstance(passphrase, str): # Chuyển passphrase sang bytes
			passphrase_bytes = passphrase.encode()
		else :
			passphrase_bytes = passphrase
		
		if isinstance(salt, str): # Chuyển salt sang bytes
			salt_bytes = base64.b64decode(salt.encode('utf-8'))
		else :
			salt_bytes = salt

		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt_bytes,
			iterations=100000,
		) # Cài đặt thuật toán

		key_goc = kdf.derive(passphrase_bytes) # Sinh khóa

		return base64.urlsafe_b64encode(key_goc) # Trả lại key đã được dùng base64 tránh lỗi
	
	def save_token(self, username:str, passphrase:str, token:str) :
		# Lưu token được mã hóa
		if self.validate_token(token) : # Kiểm tra sự tồn tại của token
			salt = os.urandom(16) # Tạo salt an toàn
			key = self._derive_key(passphrase, salt) # Sinh khóa
			f = Fernet(key)
			encrypted_token = f.encrypt(token.encode()) # Mã hóa token

			salt_str = base64.b64encode(salt).decode('utf-8') # Chuyển salt sang dạng base64 an toàn
			token_str = encrypted_token.decode('utf-8') # Chuyển token đã mã hóa sang base64 an toàn
			
			if self.config_file.exists() :
				# Mở config_file để đọc tài khoản cũ
				with open (self.config_file, "r", encoding="utf-8") as f :
					all_accounts = json.load(f)
			else :
				all_accounts = {}

			all_accounts[username] = {"salt": salt_str, "token": token_str} # Lưu thêm tài khoản

			with open (self.config_file, "w", encoding="utf-8") as f :
				# Lưu lại config_file
				json.dump(all_accounts, f, indent=4)
		
		else :
			# Trả lại khi token không tồn tại
			return "Invalid token"
	
	def check_account(self) :
		# Kiểm tra các tài khoản có trong config_file
		if self.config_file.exists() :
			# Đọc config_file
			with open (self.config_file, "r", encoding="utf-8") as f :
				all_accounts = json.load(f)
			return list(all_accounts.keys()) # Trả lại các tài khoản
		else :
			return None
	
	def load_token (self, username:str, passphrase:str) :
		# Đọc và giải mã token
		if self.config_file.exists() :
			with open (self.config_file, "r", encoding="utf-8") as f :
				# Mở và đọc config_file
				all_accounts = json.load(f)
			key = self._derive_key(passphrase, all_accounts[username]["salt"]) # Tạo key đầy đủ
			f = Fernet(key)
			try :
				# Thử giải mã
				decrypted_bytes = f.decrypt(all_accounts[username]["token"])
				return decrypted_bytes.decode("utf-8")
			except InvalidToken:
				# Bắt lỗi khi passphrase sai
				return "Passphrase wrong"
		else :
			return None

if __name__ == "__main__" : # Hàm test nếu file được chạy trực tiếp
	import sys

	print ("Đang chạy test Auth độc lập!!")

	username = input ("Đặt tên cho tài khoản test: ")
	token_lichess = input ("Đặt token thử nghiệm (có hoạt động): ")
	passphrase = input ("Đặt passphrase thử nghiệm: ")
	passphrase_wrong = passphrase + "123"
	username_2 = username + "123"

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
		auth.save_token(username_2, passphrase, token_lichess)

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

	print("Đang kiểm tra khi nhập sai passphrase")
	if auth.load_token(username, passphrase_wrong) == "Passphrase wrong" :
		print("Tính năng load_token hoạt động hoàn toàn tốt")
	else :
		print("Tính năng load_token hoạt động không ổn!")

	print("Đang dọn dẹp sau khi test!")
	if auth.config_file.exists() :
		auth.config_file.unlink()
		print("Đã xóa thành công!")
	else :
		print("File config không tồn tại!")