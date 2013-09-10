# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import hashlib
import struct

import netaddr


class SerializablePrimitive(object):
    _fmt = struct.Struct(b'<i')

    @classmethod
    def deserialize(cls, f, version=None):
        return cls._fmt.unpack(f.read(cls._fmt.size))[0]

    def serialize(self, f, version=None):
        return f.write(self._fmt.pack(self))


class BaseInt(long, SerializablePrimitive):
    def __new__(*args, **kwargs):
        return long.__new__(*args, **kwargs)

    def __repr__(self):
        return long.__repr__(self).rstrip('L')


class UInt8(BaseInt):
    _fmt = struct.Struct(b'<B')


class UInt16(BaseInt):
    _fmt = struct.Struct(b'<H')


class Int32(BaseInt):
    _fmt = struct.Struct(b'<i')


class UInt32(BaseInt):
    _fmt = struct.Struct(b'<I')


class Int64(BaseInt):
    _fmt = struct.Struct(b'<q')


class UInt64(BaseInt):
    _fmt = struct.Struct(b'<Q')


class UInt256(BaseInt):
    _fmt = struct.Struct(b'<4Q')

    @classmethod
    def deserialize(cls, f, version=None):
        words = cls._fmt.unpack(f.read(cls._fmt.size))

        int_val = 0

        for i, word in enumerate(words):
            word = word << 64 * i
            int_val = int_val | word

        return cls(int_val)

    def serialize(self, f, version=None):
        int_val = self
        max_word = 18446744073709551615

        words = []
        for _ in range(4):
            word = int_val & max_word
            words.append(int(word))
            int_val >>= 64

        return f.write(self._fmt.pack(*words))


class Bool(int, SerializablePrimitive):
    _fmt = struct.Struct(b'<?')

    def __new__(cls, value=0):
        if value:
            return int.__new__(cls, 1)

        return int.__new__(cls, 0)

    def __hash__(self):
        if self:
            return True.__hash__()

        return False.__hash__()

    def __repr__(self):
        if self:
            return 'True'

        return 'False'

    __str__ = __repr__

    def __and__(self, other):
        if isinstance(other, bool):
            return bool(int(self) & int(other))

        return int.__and__(self, other)

    __rand__ = __and__

    def __or__(self, other):
        if isinstance(other, bool):
            return bool(int(self) | int(other))

        return int.__or__(self, other)

    __ror__ = __or__

    def __xor__(self, other):
        if isinstance(other, bool):
            return bool(int(self) ^ int(other))

        return int.__xor__(self, other)


class VarInt(BaseInt):
    @classmethod
    def deserialize(cls, f, version=None):
        length = UInt8.deserialize(f, version=version)

        if length == 0xfd:
            return cls(UInt16.deserialize(f, version=version))

        elif length == 0xfe:
            return cls(UInt32.deserialize(f, version=version))

        elif length == 0xff:
            return cls(UInt64.deserialize(f, version=version))

        return cls(length)

    def serialize(self, f, version=None):
        if self < 0xfd:
            return UInt8(self).serialize(f, version=version)

        elif self <= 0xffff:
            UInt8(0xfd).serialize(f, verions=version)
            return UInt16(self).serialize(f, version=version)

        elif self <= 0xffffffff:
            UInt8(0xfe).serialize(f, verions=version)
            return UInt32(self).serialize(f, version=version)

        UInt8(0xff).serialize(f, verions=version)
        return UInt64(self).serialize(f, version=version)


class VarStr(str, SerializablePrimitive):
    @classmethod
    def deserialize(cls, f, version=None):
        length = VarInt.deserialize(f, version=version)
        return cls(f.read(length))

    def serialize(self, f, version=None):
        VarInt(len(self)).serialize(f, version=None)
        return f.write(self)


class Hash(UInt256):
    def __new__(cls, value=None, data=None, *args, **kwargs):
        if data is not None:
            value = hashlib.sha256(hashlib.sha256(data).digest()).digest()
            value = cls._fmt.unpack(value)[0]

        return UInt256.__new__(cls, value, *args, **kwargs)

    def __repr__(self):
        return '0x' + hex(self).rstrip('L').lstrip('0x').zfill(64)

    __str__ = __repr__


class Array(list, SerializablePrimitive):
    _type = Hash

    @classmethod
    def deserialize(cls, f, version=None,):
        length = VarInt.deserialize(f, version=version)
        return cls([cls._type.deserialize(f) for i in range(length)])

    def serialize(self, f, version=None):
        VarInt(len(self)).serialize(f, version=None)
        for item in self:
            item.serialize(f, version=version)


def _array(item_type=Hash):
    return type(item_type.__name__ + 'Array', (Array,), {'_type': item_type})


class CommandStr(str, SerializablePrimitive):
    @classmethod
    def deserialize(cls, f, version=None):
        return cls(f.read(12).strip(b'\x00'))

    def serialize(self, f, version=None):
        return f.write(self + b'\x00' * (12 - len(self)))


class IPAddress(netaddr.IPAddress, SerializablePrimitive):
    _fmt = struct.Struct(b'>8H')

    def __init__(self, addr, version=None, flags=0):
        addr = netaddr.IPAddress(addr, version=version, flags=flags)
        if addr.version != 6:
            addr = addr.ipv6()

        netaddr.IPAddress.__init__(self, addr, version=addr.version,
                                   flags=flags)

    @classmethod
    def deserialize(cls, f, version=None):
        words = cls._fmt.unpack(f.read(cls._fmt.size))

        int_val = 0

        for i, word in enumerate(reversed(words)):
            word = word << 16 * i
            int_val = int_val | word

        return cls(int_val)

    def serialize(self, f, version=None):
        return f.write(self._fmt.pack(*self.words))


class Checksum(SerializablePrimitive):
    _fmt = struct.Struct(b'<I')

    def __init__(self, data=None, _checksum=None):
        if data is not None:
            _hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
            _checksum = _hash[:4]

        self._repr = str(self._fmt.unpack(_checksum)[0])
        self._checksum = _checksum

    def __eq__(self, other):
        return self._checksum == other

    def __repr__(self):
        return self._repr

    __str__ = __repr__

    @classmethod
    def deserialize(cls, f, version=None):
        return cls(_checksum=f.read(cls._fmt.size))

    def serialize(self, f, version=None):
        return f.write(self._checksum)


class SerializableDict(dict, SerializablePrimitive):
    _key_map = {}
    _fields = {}

    def __init__(self, values=None, **kwargs):
        if values is not None:
            self.update(values)

        if len(kwargs):
            self.update(kwargs)

    def __setitem__(self, key, value):
        key = self._key_map.get(key, key)
        field = self._fields.get(key)

        if (value is not None and
                field is not None and
                issubclass(field, SerializablePrimitive) and
                not isinstance(value, SerializablePrimitive)):
            value = field(value)

        return dict.__setitem__(self, key, value)

    def __getitem__(self, key):
        key = self._key_map.get(key, key)
        return dict.__getitem__(self, key)

    def update(self, *args, **kwargs):
        len_args = len(args)

        if len_args > 1:
            raise TypeError('update expected at most 1 arguments, got %d' %
                            len_args)

        for k, v in dict(*args, **kwargs).iteritems():
            self[k] = v

    @classmethod
    def deserialize(cls, f, fields=None, version=None):
        if fields is None:
            fields = cls._fields

        return cls(**dict((k, v.deserialize(f, version=version))
                          for k, v in fields.iteritems()))

    def serialize(self, f, fields=None, version=None):
        if fields is None:
            fields = self._fields

        for key in fields:
            self[key].serialize(f, version=version)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ' '.join('%s=%r' % (k, self[k]) for k in self))
