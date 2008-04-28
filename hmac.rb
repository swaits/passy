#!/usr/bin/env ruby

#
# Copyright (c) 2008 Stephen Waits <steve@waits.net>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# 

require 'digest/md5'
require 'digest/rmd160'
require 'digest/sha1'
require 'digest/sha2'

# helper to make a 'length' long string filled with 'byte'
def byte_string(byte, length)
	([byte]*length).pack('C*')
end

# hmac algorithm - returns text version of hmac
def hmac(key, data, digest_object, blocksize)
	# if key is too long, hash it
	key = digest_object.digest(key) if key.size > blocksize

	# pad key out to blocksize
	key += byte_string(0,blocksize - key.size) if key.size < blocksize

	# create pads
	ipad = byte_string(0x36,blocksize)
	opad = byte_string(0x5c,blocksize)
	blocksize.times { |i| ipad[i] ^= key[i]; opad[i] ^= key[i] }

	# do the HMAC and return
	digest_object.hexdigest( opad + digest_object.digest( ipad + data ) )
end

# hmac-md5
def hmac_md5(key, data)
	hmac(key, data, Digest::MD5, 64)
end

# hmac-rmd160
def hmac_rmd160(key, data)
	hmac(key, data, Digest::RMD160, 64)
end

# hmac-sha1
def hmac_sha1(key, data)
	hmac(key, data, Digest::SHA1, 64)
end

# hmac-sha256
def hmac_sha256(key, data)
	hmac(key, data, Digest::SHA256, 64)
end

# hmac-sha384
def hmac_sha384(key, data)
	hmac(key, data, Digest::SHA384, 64)
end

# hmac-sha512
def hmac_sha512(key, data)
	hmac(key, data, Digest::SHA512, 128)
end

# test vectors courtesy of RFC2202
TestVectorsHMACMD5 = [
	[ byte_string(0xb,16),'Hi There','9294727a3638bb1c13f48ef8158bfc9d' ],
	[ 'Jefe','what do ya want for nothing?','750c783e6ab0b503eaa86e310a5db738' ],
	[ byte_string(0xaa,16),byte_string(0xdd,50),'56be34521d144c88dbb8c733f0e8b3f6' ],
	[ [1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19].pack('C*'),byte_string(0xcd,50),'697eaf0aca3a3aea3a75164746ffaa79' ],
	[ byte_string(0xc,16),'Test With Truncation','56461ef2342edc00f9bab995690efd4c' ],
	[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key - Hash Key First','6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd' ],
	[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data','6f630fad67cda0ee1fb1f562db3aa53e' ],
]
TestVectorsHMACSHA1 = [
	[ byte_string(0xb,20),'Hi There','b617318655057264e28bc0b6fb378c8ef146be00' ],
	[ 'Jefe','what do ya want for nothing?', 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79' ],
	[ byte_string(0xaa,20),byte_string(0xdd,50), '125d7342b9ac11cd91a39af48aa17b4f63f175d3' ],
	[ [1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19].pack('C*'),byte_string(0xcd,50),'4c9007f4026250c6bc8414f9bf50c86c2d7235da' ],
	[ byte_string(0xc,20),'Test With Truncation','4c1a03424b55e07fe7f27be1d58bb9324a9a5a04' ],
	[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key - Hash Key First','aa4ae5e15272d00e95705637ce8a3b55ed402112' ],
	[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data','e8e99d0f45237d786d6bbaa7965c7808bbff1a91' ],
]

# test all of the above vectors
def hmac_test
	TestVectorsHMACMD5.each do |t|
		key,data,result = t
		return false if  hmac_md5(key,data) != result
	end
	TestVectorsHMACSHA1.each do |t|
		key,data,result = t
		return false if hmac_sha1(key,data) != result
	end
	return true
end

