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

require 'digest/sha1'

# helper to make a 'length' long string filled with 'byte'
def byte_string(byte, length)
	([byte]*length).pack('C*')
end

# helper to make a 'length' long string filled with 'byte'
def byte_array(byte, length)
	([byte]*length)
end

# hmac algorithm - returns text version of hmac
def hmac(key, data, digest_object, blocksize)
	# if key is too long, hash it
	key = digest_object.digest(key) if key.size > blocksize

	# pad key out to blocksize
	key += byte_string(0,blocksize - key.size) if key.size < blocksize

	# create pads
	ipad = byte_array(0x36,blocksize)
	opad = byte_array(0x5c,blocksize)
	blocksize.times { |i| ipad[i] ^= key[i].ord; opad[i] ^= key[i].ord }

	# do the HMAC and return
	digest_object.hexdigest( opad.pack('C*') + digest_object.digest( ipad.pack('C*') + data ) )
end

# hmac-sha1
def hmac_sha1(key, data)
	hmac(key, data, Digest::SHA1, 64)
end

# test vectors courtesy of RFC2202
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
	TestVectorsHMACSHA1.each do |t|
		key,data,result = t
		return false if hmac_sha1(key,data) != result
	end
	return true
end


# make sure our hmac is working properly
if !hmac_test
	puts 'ERROR: HMAC test failed!'
	exit 1
end

# verify arguments
if ARGV.size != 2
	puts 'ERROR: Please specify password and site'
	exit 1
end

# get arguments
key,site = ARGV

# helper to split an HMAC-SHA1 into four 10-character keys
def make_passwords(key,site)
	hmac_sha1(key,site.downcase).unpack('A10A10A10A10')
end

# output
puts make_passwords(key,site)[0]

