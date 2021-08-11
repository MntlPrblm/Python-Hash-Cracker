from hashlib import md5
from urllib.request import urlopen, hashlib
import time
import os

#url containing wordlist
url_wordlist = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt'

def screen_clear():
   # for mac and linux(here, os.name is 'posix')
   if os.name == 'posix':
      _ = os.system('clear')
   else:
      # for windows platfrom
      _ = os.system('cls')

def md5crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.md5(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
           print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha224 crack
def sha224crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha224(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
           print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha1 crack
def sha1crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha1(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha256 crack
def sha256crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha256(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha384 crack
def sha384crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha384(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha512 crack
def sha512crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha512(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#blake2b crack
def blake2bcrack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.blake2b(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#blake2s crack
def blake2scrack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.blake2s(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha3_224 crack
def sha3_224crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha3_224(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha3_256 crack
def sha3_256crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha3_256(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha3_384 crack
def sha3_384crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha3_384(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#sha3_512 crack
def sha3_512crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.sha3_512(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#shake_128 crack
def shake_128crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.shake_128(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#shake_256 crack
def shake_256crack(hash):
    LIST_OF_COMMON_PASSWORDS = str(urlopen(url_wordlist).read(), 'utf-8')
    for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
        hashedGuess = hashlib.shake_256(bytes(guess, 'utf-8')).hexdigest()
        if hashedGuess == hash:
            screen_clear()
            print("The password is:", str(guess))
            quit()
        elif hashedGuess != hash:
            print("Password guess ",str(guess)," does not match, trying next...")
    screen_clear()
    print("Password not in database, we'll get them next time.")

#start function
def start():
    screen_clear()
    hash_input = input("Please input hash\n>")
    hash_input = hash_input.lower()
    hash_type = input("Please enter hash type\n>")
    hash_type = hash_type.lower()
    if hash_type == "md5":
        md5crack(hash_input)
    if hash_type == "sha1":
        sha1crack(hash_input)
    if hash_type == "sha224":
        sha224crack(hash_input)
    if hash_type == "sha256":
        sha256crack(hash_input)
    if hash_type == "sha384":
        sha384crack(hash_input)
    if hash_type == "sha512":
        sha512crack(hash_input)
    if hash_type == "blake2b":
        blake2bcrack(hash_input)
    if hash_type == "blake2s":
        blake2scrack(hash_input)
    if hash_type == "sha3_224":
        sha3_224crack(hash_input)
    if hash_type == "sha3_256":
        sha3_256crack(hash_input)
    if hash_type == "sha3_384":
        sha3_384crack(hash_input)
    if hash_type == "sha3_512":
        sha3_512crack(hash_input)
    if hash_type == "shake_128":
        shake_128crack(hash_input)
    if hash_type == "shake_256":
        shake_256crack(hash_input)
    else:
        screen_clear()
        print("Please only enter hashes that are: sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, md5, sha3_224, sha3_256, sha3_384, sha3_512, shake_128, or shake_256")
        time.sleep(3)
        start()


    




if __name__=="__main__":
    start()