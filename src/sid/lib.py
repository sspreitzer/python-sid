'''
The lib contains exceptions, constants and the sid class
'''


import base64
import struct
import string
import binascii


SID_STRING = 0
SID_BINARY = 1
SID_BASE64 = 2


class sidException(Exception):
    '''
    Base exception derived from Exception class
    '''
    pass


class sidExceptionNoSuchType(sidException):
    '''
    No such type exception. Used when class is not initialized properly.
    '''
    pass


class sid(object):
    '''
    Class to manage Windows SIDs
    '''
    def __init__(self, data, sidtype=SID_STRING):
        '''
        Initialize class with either a string, binary or base64 sid.
        For example, Anonymous user is string 'S-1-5-7'
        '''
        if sidtype == SID_STRING:
            self._sid = data
            return
        elif sidtype == SID_BINARY:
            self._sid = self.strsid(data)
            return
        elif sidtype == SID_BASE64:
            self._sid = self.b64Strsid(data)
            return
        else:
            raise sidExceptionNoSuchType()
    
    def ldap(self):
        '''
        Return ldap filter version of sid
        '''
        return self.byteldap(self._sid)
    
    def binary(self):
        '''
        Return binary version of sid
        '''
        return self.byte(self._sid)

    def base64(self):
        '''
        Return base64 encoded version of binary sid
        '''
        return self.byteB64(self._sid)
    
    def str(self):
        '''
        Return sid as a string
        '''
        return str(self)
    
    def __str__(self):
        '''
        sid class can be used as a string
        '''
        return self._sid
    
    def __repr__(self):
        '''
        Return representation of sid
        '''
        return repr( self._sid )

    @classmethod
    def longToByte(cls, integer, little_endian=True, size=4):
        '''
        Convert a Python integer into bytes
            integer - integer to convert
            little_endian - True (default) or False for little or big endian
            size - size to be returned, default is 4 (thats 32bit)
        '''
        if little_endian:
            return struct.pack('<q', integer)[0:size]
        else:
            return struct.pack('>q', integer)[8-size:]
    
    @classmethod
    def byteToLong(cls, byte, little_endian=True):
        '''
        Convert bytes into a Python integer
            byte - bytes to convert
            little_endian - True (default) or False for little or big endian
        '''
        if len(byte) > 8:
            raise Exception('Bytes too long. Needs to be <= 8 or 64bit')
        else:
            if little_endian:
                a = string.ljust(byte, 8, '\x00')
                return struct.unpack('<q', a)[0]
            else:
                a = string.rjust(byte, 8, '\x00')
                return struct.unpack('>q', a)[0]  
 
    @classmethod
    def strsid(cls, byte):
        '''
        Convert bytes into a string SID
            byte - bytes to convert
        '''
        ret = 'S'
        sid = []
        sid.append(cls.byteToLong(byte[0]))
        sid.append(cls.byteToLong(byte[2:2+6], False))
        for i in range(8, len(byte), 4):
            sid.append(cls.byteToLong(byte[i:i+4]))
        for i in sid:
            ret += '-' + str(i)
        return ret
    
    @classmethod
    def byte(cls, strsid):
        '''
        Convert a SID into bytes
            strdsid - SID to convert into bytes
        '''
        sid = string.split(strsid, '-')
        ret = ''
        sid.remove('S')
        for i in range(len(sid)):
            sid[i] = int(sid[i])
        sid.insert(1, len(sid)-2)
        ret += cls.longToByte(sid[0], size=1)
        ret += cls.longToByte(sid[1], size=1)
        ret += cls.longToByte(sid[2], False, 6)
        for i in range(3, len(sid)):
            ret += cls.longToByte(sid[i])
        return ret
    
    @classmethod
    def byteldap(cls, strsid):
        '''
        Encode a sid into AD ldap search form
            strsid - SID to encode
        '''
        ret = ''
        a = binascii.hexlify(cls.byte(strsid))
        print a
        for i in range(0, len(a), 2):
            ret += '\\' + a[i:i+2]
        return ret
    
    @classmethod
    def byteB64(cls, strsid):
        '''
        Encode a sid into base64
            strsid - SID to encode
        '''
        return base64.b64encode(cls.byte(strsid))
    
    @classmethod
    def b64Strsid(cls, data):
        '''
        Decode a base64 SID into string
            data - base64 encoded sid
        '''
        return cls.strsid(base64.b64decode(data))
