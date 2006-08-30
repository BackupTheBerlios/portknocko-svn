# Copyright (c) 2001, 2002 Allan Saddi <allan@saddi.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import sha512c

__all__ = ['sha512']

blocksize = 1
digestsize = 64

class sha512(object):
    """Return a new SHA512 hashing object.

    An optional string argument may be provided; if present, this string
    will be  automatically hashed.
    """

    blocksize = blocksize
    digestsize = digestsize
    
    def __init__(self, s=None):
        self.shaContext = sha512c.new__SHA512Context()
        sha512c.SHA512Init (self.shaContext)
        if s is not None:
            if type(s) is not str:
                raise TypeError, "sha512() argument 1 must be string"
            self.update(s)
    
    def __del__(self):
        sha512c.SHA512Sanitize(self.shaContext)
        sha512c.delete__SHA512Context(self.shaContext)

    def update(self, s):
        """Update this hashing object's state with the provided string."""
        if type(s) is not str:
            raise TypeError, "update() argument 1 must be string"
        sha512c.SHA512Update(self.shaContext, s, len(s))

    def digest(self):
        """Return the digest value as a string of binary data."""
        return sha512c.MySHA512Final(self.shaContext)
    
    def hexdigest(self):
        """Return the digest value as a string of hexadecimal digits."""
        hash = self.digest()
        hexhash = ''
        for c in hash:
            hexhash += '%02x' % ord(c)
        return hexhash

    def copy(self):
        "Return a copy of the hashing object."
        newSelf = sha512()
        sha512c.SHA512Copy(self.shaContext, newSelf.shaContext)
        return newSelf

def new(s=None):
    """Return a new SHA512 hashing object.

    An optional string argument may be provided; if present, this string
    will be  automatically hashed.
    """
    if s is not None:
        if type(s) is not str:
            raise TypeError, "new() argument 1 must be string"
    return sha512(s)

if __name__ == '__main__':
    print sha512('abc').hexdigest()
    print sha512('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn' \
                 'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu').hexdigest()
    h = sha512()
    s = 'a'*1000
    for i in range(1000):
        h.update(s)
    print h.hexdigest()
    del h