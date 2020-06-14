import requests
import hashlib
import sys

def request_api_data(query_char):
	# use only first five characters of the sha1 hash password to hash
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
	    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again!')
	return res

def get_password_leaks_count(hashes, tail_hash_to_check):
	# splits the hashed password through (:) and stores into a tuple 
	hashes = (line.split(':') for line in hashes.text.splitlines())
	# loops through hashes tuple
	for h,count in hashes:
		# checks multiple hash tails, to know if there are any equals to the password's hash_tail
		if h == tail_hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	# check password if it exists in API response
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	# store first 5 char from the hashed_passwords, and remaining char in the hashed
	first5_char, tail = sha1password[:5], sha1password[5:]
	# 200 is a good response, 400 is bad!
	response = request_api_data(first5_char)
	# returns the response data from the api and the tail of the hashed_sha1_hexdigest_password
	return get_password_leaks_count(response, tail)

# main function
def main(args):
	# loops through the command line for passwords
	for password in args:
		# stores password in the command line argument each time it loops
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times. I would advice you change your password')
		else:
			print(f'{password} was NOT found. Carry on!')
	return 'done!'

if __name__ == '__main__':
	# sys.exit, exits the for loop in the main function and returns "done!" from the main function
	sys.exit(main(sys.argv[1:]))
