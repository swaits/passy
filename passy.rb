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

require_relative 'hmac'

# list of sites we visit
Sites = %w(
	apple.com
	thawte.com
	adp.com
	amazon.com
	apmex.com
	boardgamegeek.com
	bulkregister.com
	directv.com
	facebook.com
	google.com
	intrade.com
	lendingclub.com
	ma.gnolia.com
	mahaenergy.com
	mint.com
	netflix.com
	paypal.com
)

# make sure our hmac is working properly
if !hmac_test
	puts 'ERROR: HMAC test failed!'
	exit 1
end

# make sure no arguments specified (as these will mess up 'gets' below)
if ARGV.size > 0
	puts 'ERROR: Do not specify any arguments.'
	exit 1
end

# prompt for password
print ' Enter Password: '
Key = gets.chomp
print 'Verity Password: '
if Key != gets.chomp
	puts 'Error: passwords do not match.'
	exit 1
end

# helper to split an HMAC-SHA1 into four 10-character keys
def make_passwords(key,site)
	hmac_sha1(key,site.downcase).unpack('A10A10A10A10')
end

# output report
puts
Format = '%-30s  %10s  %10s  %10s  %10s'
puts Format % [ 'Site', 'Password 1', 'Password 2', 'Password 3', 'Password 4' ]
puts Format % [ '-'*30, '----------', '----------', '----------', '----------' ]
Sites.sort.each do |s|
	p = make_passwords(Key,s)
	puts Format % [ s, p[0], p[1], p[2], p[3] ]
end


