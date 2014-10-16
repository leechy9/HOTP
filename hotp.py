'''
Generates HOTP values of various lengths.
Written for Python 3.3
Copyright (C) 2014 leechy9

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
'''

import hashlib
import hmac

def hotp(key, count, digits=8):
  '''
  Generates HOTP values from the given key and count.
  Args:
    key - the byte-string (length 20) representing the secret key
    count - the number of previous times a HOTP has been generated
    digits - optional, tells how many HOTP digits to generate
  Return - the string representation of the HOTP value, left padded with zeroes
  '''
  byte_count = count.to_bytes(8, byteorder='big')
  hashed = hmac.new(key, byte_count, hashlib.sha1)
  hmac_val = hashed.digest()
  offset = hmac_val[19] & 0xf
  bin_code = (hmac_val[offset] & 0x7f) << 24 \
   | ((hmac_val[offset+1] & 0xff) << 16) \
   | ((hmac_val[offset+2] & 0xff) << 8) \
   | (hmac_val[offset+3] & 0xff)
  truncated = bin_code % (10**digits)
  return '{0:0{1}d}'.format(truncated, digits)
