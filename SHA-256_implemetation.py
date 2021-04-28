'''
Implementing the FIPS PUB 180-4 description for calculating SHA-256 hash function
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

Written for eductation purpose only
'''


import math
from itertools import count, islice

# SHA-256 Functions

def rotr(x, n, size=32):
	return (x >> n) | (x << size-n)

def shr(x, n):
	return x >> n

def ch(x, y, z):
	return (x & y) ^ (~x & z)

def maj(x, y, z):
	return (x & y) ^ (x & z) ^ (y & z)

def summation0(x):
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def summation1(x):
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0(x):
	return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1(x):
	return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def bytes_to_integer(x):
	return int.from_bytes(x, 'big')

def integer_to_bytes(x):
	return x.to_bytes(4, 'big')

# SHA-256 constants

def convert_prime_fraction_to_hex(prime, n, hex_chars):
	root = prime ** (1/n)
	frac_part = root - math.floor(root)
	return math.floor(frac_part*(16**hex_chars))

def generate_n_primes(n):
	primes = (n for n in count(2) if all(n % d for d in range(2, n)))
	return islice(primes, 0, n)

def gen_keys():
	# these constants are the first 32 bits of the fractional parts of cube root of first 64 prime numbers
	return [convert_prime_fraction_to_hex(p, 3, 8) for p in generate_n_primes(64)]

def gen_initial_hash():
	# the initial hash value is the first 32 bits of the fractional parts of square root of first 8 prime numbers
	return [convert_prime_fraction_to_hex(p, 2, 8) for p in generate_n_primes(8)]


#Funtion to pad the message
def padding(msg):
	msg = bytearray(msg)
	l = len(msg) * 8
	msg.append(0b10000000)

	while(len(msg)*8 % 512 != 448):
		msg.append(0x00)

	msg.extend(l.to_bytes(8, 'big'))
	return msg

# Function to parse the message into block of 512 bits 
def parsing(msg):
	return [msg[i:i+64] for i in range(0, len(msg), 64)]


def sha256(msg: bytes) -> bytes:
	key = gen_keys()

	# padding the message
	msg = padding(msg)

	# parse the message into the blocks of 512 bits
	msg_blocks = parsing(msg)

	# Get the initial hash value
	hash_value = gen_initial_hash()

	# Loop for each message block M(1), M(2),..... M(n)
	for msg_block in msg_blocks:
		msg_schedule = []

		#Perpare the message schedule
		for t in range(64):

			if t <= 15:
				# message schedule is the same as message blocks for first 16 words
				msg_schedule.append(bytes(msg_block[t*4:t*4+4]))
			else:
				t_1 = sigma1(bytes_to_integer(msg_schedule[t-2]))
				t_2 = bytes_to_integer(msg_schedule[t-7])
				t_3 = sigma0(bytes_to_integer(msg_schedule[t-15]))
				t_4 = bytes_to_integer(msg_schedule[t-16])
				total = (t_1 + t_2 + t_3 + t_4) % 2**32
				msg_schedule.append(integer_to_bytes(total))

	# Initalize the eight variables a,b,c,d,ef,g,h with the inital hash value
	a, b, c, d, e, f, g, h = hash_value

	for t in range(64):
		temp_1 = h + summation1(e) + ch(e, f, g) + key[t] + bytes_to_integer(msg_schedule[t]) % 2**32
		temp_2 = summation0(a) + maj(a, b, c) % 2**32
		h = g
		g = f
		f = e
		e  = (d + temp_1) % 2**32
		d = c
		c = b
		b = a
		a = (temp_1 + temp_2) % 2**32

	# Compute the intermediate hash value
	variables = [a, b, c, d, e, f, g, h]

	H = []
	for i, j in zip(hash_value, variables):
		H.append((i+j) % 2**32)

	return b''.join(integer_to_bytes(i) for i in H)

if __name__ == '__main__':
	print(sha256(b'abc').hex())