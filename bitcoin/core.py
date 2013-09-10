
#
# core.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import cStringIO
import itertools

import collections
import struct

from bitcoin import serialize
from bitcoin import coredefs
from bitcoin import script
from bitcoin import _types


class NetAddr(_types.SerializableDict):
    _key_map = {'protover': 'version',
                'nTime': 'time',
                'nServices': 'services'}

    _fields = collections.OrderedDict([('time', _types.UInt32),
                                       ('services', _types.UInt64),
                                       ('ip', _types.IPAddress),
                                       ('port', _types.UInt16)])

    def __init__(self, time=0, services=1, port=0,
                 version=coredefs.PROTO_VERSION, *args, **kwargs):

        kwargs['time'] = time
        kwargs['services'] = services
        kwargs['port'] = port
        kwargs['version'] = version

        if 'ip' not in kwargs:
            kwargs['ip'] = _types.IPAddress('::')

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @classmethod
    def deserialize(cls, f, version=None):
        version = version if version is not None else coredefs.PROTO_VERSION
        fields = cls._fields.copy()

        if version is not None and version < coredefs.CADDR_TIME_VERSION:
            del fields['time']

        return _types.SerializableDict.deserialize.im_func(cls, f, fields,
                                                           version)

    def serialize(self, f, version=None):
        version = version if version is not None else self['version']
        fields = self._fields.copy()

        if version is not None and version < coredefs.CADDR_TIME_VERSION:
            del fields['time']

        return _types.SerializableDict.serialize(self, f, fields, version)


class Inv(_types.SerializableDict):
    typemap = {0: 'Error',
               1: 'TX',
               2: 'Block'}

    _fields = collections.OrderedDict([('type', _types.UInt32),
                                       ('hash', _types.Hash)])

    def __init__(self, version=coredefs.PROTO_VERSION, *args, **kwargs):

        if '_type' in kwargs:
            kwargs['type'] = kwargs['_type']
            del kwargs['_type']

        if '_hash' in kwargs:
            kwargs['hash'] = kwargs['_hash']
            del kwargs['_hash']

        if 'type' not in kwargs:
            kwargs['type'] = 0

        if 'hash' not in kwargs:
            kwargs['hash'] = 0

        kwargs['version'] = version

        _types.SerializableDict.__init__(self, *args, **kwargs)


class BlockLocator(_types.SerializableDict):
    _key_map = {'nVersion': 'version',
                'vHave': 'block_locator_hashes'}

    _fields = collections.OrderedDict([('version', _types.UInt32),
                                       ('block_locator_hashes',
                                        _types._array(_types.Hash)),
                                       ('hash_stop', _types.Hash)])

    def __init__(self, hash_stop=0, version=coredefs.PROTO_VERSION,
                 *args, **kwargs):

        kwargs['version'] = version
        kwargs['hash_stop'] = hash_stop

        if 'block_locator_hashes' not in kwargs:
            kwargs['block_locator_hashes'] = []

        _types.SerializableDict.__init__(self, *args, **kwargs)


class OutPoint(_types.SerializableDict):
    _fields = collections.OrderedDict([('hash', _types.Hash),
                                       ('index', _types.UInt32)])

    def __init__(self, index=None, version=coredefs.PROTO_VERSION,
                 *args, **kwargs):

        kwargs['index'] = index

        if '_hash' in kwargs:
            kwargs['hash'] = kwargs['_hash']
            del kwargs['_hash']

        if 'hash' not in kwargs:
            kwargs['hash'] = 0

        kwargs['version'] = version

        _types.SerializableDict.__init__(self, *args, **kwargs)

    def __nonzero__(self):
        return self['hash'] == 0 and self['index'] is None


class TxIn(_types.SerializableDict):
    _key_map = {'previous': 'previous_output',
                'prevout': 'previous_output',
                'scriptSig': 'signature_script',
                'nSequence': 'sequence'}

    _fields = collections.OrderedDict([('previous_output', OutPoint),
                                       ('signature_script', _types.VarStr),
                                       ('sequence', _types.UInt32)])

    def __init__(self, signature_script=b'', sequence=0xffffffff,
                 version=coredefs.PROTO_VERSION, *args, **kwargs):
        kwargs['signature_script'] = signature_script
        kwargs['sequence'] = sequence

        if 'previous_output' not in kwargs:
            kwargs['previous_output'] = OutPoint()

        kwargs['version'] = version

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @property
    def final(self):
        return self['sequence'] == 0xffffffff

    @property
    def valid(self):
        if script.CSript().tokenize(self['signature_script']):
            return True

        return False


class TxOut(_types.SerializableDict):
    _key_map = {'nValue': 'value',
                'scriptPubKey': 'pk_script'}

    _fields = collections.OrderedDict([('value', _types.Int64),
                                       ('pk_script', _types.VarStr)])

    def __init__(self, value=-1, pk_script=b'',
                 version=coredefs.PROTO_VERSION, *args, **kwargs):
        kwargs['value'] = value
        kwargs['pk_script'] = pk_script

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @property
    def valid(self):
        if (0 <= self['value'] <= coredefs.MAX_MONEY and
                script.CScript().tokenize(self['pk_script'])):
            return True

        return False


class Transaction(_types.SerializableDict):
    _key_map = {'nVersion': 'version',
                'vin': 'tx_in',
                'vout': 'tx_out',
                'nLockTime': 'lock_time'}

    _fields = collections.OrderedDict([('version', _types.UInt32),
                                       ('tx_in', _types._array(TxIn)),
                                       ('tx_out', _types._array(TxOut)),
                                       ('lock_time', _types.UInt32)])

    def __init__(self, lock_time=0, version=coredefs.PROTO_VERSION,
                 *args, **kwargs):
        kwargs['version'] = version
        kwargs['lock_time'] = lock_time

        if 'tx_in' not in kwargs:
            kwargs['tx_in'] = []

        if 'tx_out' not in kwargs:
            kwargs['tx_out'] = []

        _types.SerializableDict.__init__(self, *args, **kwargs)

    # NOTE Fields that need to be implementated
    #    self.nFeesPaid = 0
    #    self.dFeePerKB = None
    #    self.dPriority = None
    #    self.ser_size = 0

    def __nonzero__(self):
        return self['tx_in'] and self['tx_out']

    @property
    def sha256(self):
        if not hasattr(self, '_sha256'):
            self.calc_sha256()
        return self._sha256

    def calc_sha256(self):
        f = cStringIO.StringIO()
        self.serialize(f, version=self['version'])
        self._sha256 = _types.Hash(data=f.getvalue())
        return self._sha256

    @property
    def valid(self):
        if not self['tx_in'] or not self['tx_out']:
            return False

        # TODO check the serialized size
        # https://github.com/bitcoin/bitcoin/blob/master/src/main.cpp#L703

        if not all([tx.valid for tx in self['tx_out']]):
            return False

        value = sum([tx['value'] for tx in self['tx_out']])
        if not (0 <= value <= coredefs.MAX_MONEY):
            return False

        inputs = set([tx['previous_output'] for tx in self['tx_in']])
        if len(inputs) != len(self['tx_in']):
            return False

        if self.coinbase:
            if not (2 <= self['tx_in'][0]['signature_script'] <= 100):
                return False

        else:
            if not all(inputs):
                return False

        return True

    @property
    def final(self):
        if all([tx.final for tx in self['tx_in']]):
            return True

        return False

    @property
    def coinbase(self):
        return len(self['tx_in']) == 1 and self['tx_in'][0].prevout


class Block(_types.SerializableDict):
    _key_map = {'nVersion': 'version',
                'hashPrevBlock': 'prev_block',
                'hashMerkleRoot': 'merkle_root',
                'nTime': 'timestamp',
                'nBits': 'bits',
                'nNonce': 'nonce',
                'vtx': 'txns'}

    _fields = collections.OrderedDict([('version', _types.UInt32),
                                       ('prev_block', _types.Hash),
                                       ('merkle_root', _types.Hash),
                                       ('timestamp', _types.UInt32),
                                       ('bits', _types.UInt32),
                                       ('nonce', _types.UInt32),
                                       ('txns', _types._array(Transaction))])

    def __init__(self, prev_block=0, merkle_root=0, timestamp=0, bits=0,
                 nonce=0, version=coredefs.PROTO_VERSION, *args, **kwargs):

        kwargs['version'] = version
        kwargs['prev_block'] = prev_block
        kwargs['merkle_root'] = merkle_root
        kwargs['timestamp'] = timestamp
        kwargs['bits'] = bits
        kwargs['nonce'] = nonce

        if 'txns' not in kwargs:
            kwargs['txns'] = []

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @property
    def sha256(self):
        if not hasattr(self, '_sha256'):
            self.calc_sha256()

        return self._sha256

    def calc_sha256(self):
        f = cStringIO.StringIO()
        self['version'].serialize(f, version=self['version'])
        self['prev_block'].serialize(f, version=self['version'])
        self['merkle_root'].serialize(f, version=self['version'])
        self['timestamp'].serialize(f, version=self['version'])
        self['bits'].serialize(f, version=self['version'])
        self['nonce'].serialize(f, version=self['version'])

        self._sha256 = _types.Hash(data=f.getvalue())
        return self._sha256

    @property
    def merkle(self):
        if not hasattr(self, '_merkle'):
            self.calc_merkle()

        return self._merkle

    def calc_merkle(self):
        hashes = [tx.sha256 for tx in self['txns'] if tx.valid]

        if len(hashes) != len(self['txns']):
            return None

        while (len(hashes) / 2) % 2 != 0:
            hashes.append(hashes[-1])

        for right, left in itertools.izip(*([reversed(hashes)] * 2)):
            hashes.insert(0, _types.Hash(data=left + right))

        self._merkle_tree = hashes
        self._merkle = hashes[0]
        return self._merkle

    @property
    def valid(self):
        if (self.sha256 < self['bits'] and
                self.merkle == self['merkle_root']):
            return True

        return False


class CUnsignedAlert(object):

    def __init__(self):
        self.nVersion = 1
        self.nRelayUntil = 0
        self.nExpiration = 0
        self.nID = 0
        self.nCancel = 0
        self.setCancel = []
        self.nMinVer = 0
        self.nMaxVer = 0
        self.setSubVer = []
        self.nPriority = 0
        self.strComment = b""
        self.strStatusBar = b""
        self.strReserved = b""

    def deserialize(self, f):
        self.nVersion = struct.unpack(b"<i", f.read(4))[0]
        self.nRelayUntil = struct.unpack(b"<q", f.read(8))[0]
        self.nExpiration = struct.unpack(b"<q", f.read(8))[0]
        self.nID = struct.unpack(b"<i", f.read(4))[0]
        self.nCancel = struct.unpack(b"<i", f.read(4))[0]
        self.setCancel = serialize.deser_int_vector(f)
        self.nMinVer = struct.unpack(b"<i", f.read(4))[0]
        self.nMaxVer = struct.unpack(b"<i", f.read(4))[0]
        self.setSubVer = serialize.deser_string_vector(f)
        self.nPriority = struct.unpack(b"<i", f.read(4))[0]
        self.strComment = serialize.deser_string(f)
        self.strStatusBar = serialize.deser_string(f)
        self.strReserved = serialize.deser_string(f)

    def serialize(self):
        r = b""
        r += struct.pack(b"<i", self.nVersion)
        r += struct.pack(b"<q", self.nRelayUntil)
        r += struct.pack(b"<q", self.nExpiration)
        r += struct.pack(b"<i", self.nID)
        r += struct.pack(b"<i", self.nCancel)
        r += serialize.ser_int_vector(self.setCancel)
        r += struct.pack(b"<i", self.nMinVer)
        r += struct.pack(b"<i", self.nMaxVer)
        r += serialize.ser_string_vector(self.setSubVer)
        r += struct.pack(b"<i", self.nPriority)
        r += serialize.ser_string(self.strComment)
        r += serialize.ser_string(self.strStatusBar)
        r += serialize.ser_string(self.strReserved)
        return r

    def __repr__(self):
        return ("CUnsignedAlert(nVersion %d, nRelayUntil %d, "
                "nExpiration %d, nID %d, nCancel %d, nMinVer %d, "
                "nMaxVer %d, nPriority %d, strComment %s, "
                "strStatusBar %s, strReserved %s)" %
                (self.nVersion, self.nRelayUntil, self.nExpiration,
                 self.nID, self.nCancel, self.nMinVer, self.nMaxVer,
                 self.nPriority, self.strComment, self.strStatusBar,
                 self.strReserved))


class CAlert(object):

    def __init__(self):
        self.vchMsg = b""
        self.vchSig = b""

    def deserialize(self, f):
        self.vchMsg = serialize.deser_string(f)
        self.vchSig = serialize.deser_string(f)

    def serialize(self):
        r = b""
        r += serialize.ser_string(self.vchMsg)
        r += serialize.ser_string(self.vchSig)
        return r

    def __repr__(self):
        return "CAlert(vchMsg.sz %d, vchSig.sz %d)" % (len(self.vchMsg),
                                                       len(self.vchSig))
