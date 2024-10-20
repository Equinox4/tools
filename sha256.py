#!/usr/bin/env python3
"""This is an implementation of the Secure Hash Algorithm SHA-256 based on the RFC 6234
Usage: {script_name} <filename>
"""

import os
import sys

BLOCK_SIZE_BYTE = 64

def rotr(x: int, n: int) -> int :
	"""Binary right rotate number x by n

		SHA-256 operate on 32-bit words
	"""

	return (x >> n) | ((x << (32 - n)) % 2 ** 32)

# Functions ch, maj, bsig0, bsig1, ssig0, ssig1, see rfc6234#section-5.1
def ch(x: int, y: int, z: int) -> int:
	return (x & y) ^ ((~x) & z)

def maj(x: int, y: int, z: int) -> int:
	return (x & y) ^ (x & z) ^ (y & z)

def bsig0(x: int) -> int:
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def bsig1(x: int) -> int:
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ssig0(x: int) -> int:
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def ssig1(x: int) -> int:
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


# K constants, see rfc6234#section-5.1
K = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Hash initialization, see rfc6234#section-6.1
H = [
	0x6a09e667, 0xbb67ae85,
	0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19,
]

# Pad message on the right to get length L % 512 == 0, see rfc6234#section-4.1
def perform_padding(chunck: bytes, input_size: int) -> bytes:
	assert len(chunck) <= 64,\
		f'perform_padding(chunck, input_size): Bad block size, must be <= 512 bits (64 bytes) got {len(chunck)}.'
	assert input_size < 2 ** 64,\
		f'perform_padding(chunck, input_size): Bad input_size, must be < 2^64 bits got {input_size}.'

	block = bytearray(chunck)
	l = input_size

	# We have to substract 7 zeros from 447 because we works with bytes (8 bits)
	k = (440 - l) % 512

	block.extend(b'\x80') # 0b10000000
	block.extend(b'\x00' * (k >> 3))
	block.extend(l.to_bytes(8, byteorder = 'big', signed = False))

	return bytes(block)

def compute_hash(block: bytes) -> None:
	assert len(block) == BLOCK_SIZE_BYTE,\
		f'compute_hash(block): Bad block size, must be 512 bits (64 bytes) got {len(block)}.'

	words = []

	words_count = len(block) >> 2 # 32 bits words
	for wi in range(words_count):
		words.append(int.from_bytes(block[wi * 4:wi * 4 + 4], byteorder = 'big', signed = False))

	for wi in range(16, BLOCK_SIZE_BYTE):
		word = (ssig1(words[wi - 2]) + words[wi - 7] + ssig0(words[wi - 15]) + words[wi - 16]) % 2 ** 32
		words.append(word)

	a, b, c, d, e, f, g, h = H[0:]

	for t in range(0, BLOCK_SIZE_BYTE):
		t1 = (h + bsig1(e) + ch(e, f, g) + K[t] + words[t]) % 2 ** 32
		t2 = (bsig0(a) + maj(a, b, c)) % 2 ** 32
		h = g
		g = f
		f = e
		e = (d + t1) % 2 ** 32
		d = c
		c = b
		b = a
		a = (t1 + t2) % 2 ** 32

	for i, x in enumerate([a, b, c, d, e, f, g, h]):
		H[i] = (x + H[i]) % 2 ** 32


def main() -> str:
	if len(sys.argv) != 2:
		print(__doc__.format(script_name = os.path.basename(__file__)), file = sys.stderr)
		exit(0)

	file = sys.argv[1]
	if not os.path.isfile(file):
		print(f'The provided file "{file}" could not be found.', file = sys.stderr)
		exit(0)

	file_size = os.stat(file).st_size * 8 # message length in bits
	if file_size >= 2 ** 64:
		print(f'The provided file "{file}" is too big.', file = sys.stderr)
		exit(0)

	# empty file, no need to read it
	if file_size == 0:
		block = perform_padding(b'', file_size)
		compute_hash(block)
	else:
		nb_chuncks = file_size >> 9
		if file_size % (BLOCK_SIZE_BYTE * 8):
			nb_chuncks += 1

		with open(file, 'rb') as f:
			while chunck := f.read(BLOCK_SIZE_BYTE):
				# pad only the last chunck
				if nb_chuncks == 1:
					chunck = perform_padding(chunck, file_size)

				# there are edge cases where the padding adds enought 0 to make a new chunck
				for i in range(0, len(chunck), BLOCK_SIZE_BYTE):
					compute_hash(chunck[i:i + BLOCK_SIZE_BYTE])

				nb_chuncks -= 1

	return ''.join(map(lambda h: f'{h:x}', H))

if __name__ == "__main__":
	print(main())