
#
# messages.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import collections
import cStringIO
import hashlib
import random
import struct
import time as pytime

from bitcoin import core
from bitcoin import coredefs
from bitcoin import serialize
from bitcoin import _types

MSG_TX = 1
MSG_BLOCK = 2


class Message(_types.SerializableDict):
    _fields = collections.OrderedDict([('magic', _types.UInt32),
                                       ('command', _types.CommandStr),
                                       ('length', _types.UInt32),
                                       ('checksum', _types.Checksum)])

    def __init__(self, magic, payload, length=None, checksum=None, *args,
                 **kwargs):
        self._fields['payload'] = type(payload)

        kwargs['magic'] = magic
        kwargs['payload'] = payload
        kwargs['length'] = length
        kwargs['checksum'] = checksum

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @classmethod
    def deserialize(cls, f, version=None):
        magic = cls._fields['magic'].deserialize(f, version=version)
        command = cls._fields['command'].deserialize(f, version=version)
        length = cls._fields['length'].deserialize(f, version=version)
        checksum = cls._fields['checksum'].deserialize(f, version=version)

        payload = MESSAGE_MAP[command].deserialize(f, version=version)

        return cls(magic=magic, length=length, checksum=checksum,
                   payload=payload, command=command)

    def serialize(self, f, version=None):
        data = cStringIO.StringIO()
        self['payload'].serialize(data, version=version)
        data = data.getvalue()

        self['magic'].serialize(f, version=version)
        command = self._fields['command'](self['payload'].command)
        command.serialize(f, version=version)
        self._fields['length'](len(data)).serialize(f, version=version)
        self._fields['checksum'](data).serialize(f, version=version)
        f.write(data)


class Version(_types.SerializableDict):
    command = b'version'
    _key_map = {'protover': 'version',
                'nVersion': 'version',
                'nServices': 'services',
                'nTime': 'time',
                'addrTo': 'addr_recv',
                'addr_to': 'addr_recv',
                'addrFrom': 'addr_from',
                'nNonce': 'nonce',
                'strSubVersion': 'user_agent',
                'nStartingHeight': 'start_height'}

    _fields = collections.OrderedDict([('version', _types.Int32),
                                       ('services', _types.UInt64),
                                       ('time', _types.Int64),
                                       ('addr_recv', core.NetAddr),
                                       ('addr_from', core.NetAddr),
                                       ('nonce', _types.UInt64),
                                       ('user_agent', _types.VarStr),
                                       ('start_height', _types.Int32),
                                       ('relay', _types.Bool)])

    def __init__(self, version=coredefs.PROTO_VERSION, services=1,
                 user_agent=b'/python-bitcoin-0.0.1/',  start_height=-1,
                 relay=False, *args, **kwargs):
        if version == 10300:
            version = 300

        kwargs['version'] = version
        kwargs['services'] = services
        kwargs['user_agent'] = user_agent
        kwargs['start_height'] = start_height
        kwargs['relay'] = relay

        if 'time' not in kwargs:
            kwargs['time'] = pytime.time()

        if 'addr_recv' not in kwargs:
            kwargs['addr_recv'] = core.NetAddr()

        if 'addr_from' not in kwargs:
            kwargs['addr_from'] = core.NetAddr()

        if 'nonce' not in kwargs:
            kwargs['nonce'] = random.getrandbits(64)

        _types.SerializableDict.__init__(self, *args, **kwargs)

    @classmethod
    def deserialize(cls, f, version=None):
        # NOTE Version.deserialize will always ignore the passed version
        #      and read it from the stream instead
        version = cls._fields['version'].deserialize(f)

        if version == 10300:
            version = 300

        def deserialize(field):
            return cls._fields[field].deserialize(f, version=version)

        services = deserialize('services')
        time = deserialize('time')
        addr_recv = cls._fields['addr_recv'].deserialize(f, version=0)
        addr_from = None
        nonce = None
        user_agent = None
        start_height = None
        relay = None

        if version >= 106:
            addr_from = cls._fields['addr_from'].deserialize(f, version=0)
            nonce = deserialize('nonce')
            user_agent = deserialize('user_agent')

            if version >= 209:
                start_height = deserialize('start_height')

                if version >= 70001:
                    relay = deserialize('relay')

        return cls(version=version, services=services, time=time,
                   addr_recv=addr_recv, addr_from=addr_from, nonce=nonce,
                   user_agent=user_agent, start_height=start_height,
                   relay=relay)


class VerAck(_types.SerializableDict):
    command = b'verack'


class msg_addr(object):
    command = b"addr"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.addrs = []

    def deserialize(self, f):
        self.addrs = serialize.deser_vector(f, core.CAddress, self.protover)

    def serialize(self):
        return serialize.ser_vector(self.addrs)

    def __repr__(self):
        return "msg_addr(addrs=%s)" % (repr(self.addrs))


class msg_alert(object):
    command = b"alert"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.alert = core.CAlert()

    def deserialize(self, f):
        self.alert = core.CAlert()
        self.alert.deserialize(f)

    def serialize(self):
        r = b""
        r += self.alert.serialize()
        return r

    def __repr__(self):
        return "msg_alert(alert=%s)" % (repr(self.alert), )


class msg_inv(object):
    command = b"inv"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.inv = []

    def deserialize(self, f):
        self.inv = serialize.deser_vector(f, core.CInv)

    def serialize(self):
        return serialize.ser_vector(self.inv)

    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))


class msg_getdata(object):
    command = b"getdata"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.inv = []

    def deserialize(self, f):
        self.inv = serialize.deser_vector(f, core.CInv)

    def serialize(self):
        return serialize.ser_vector(self.inv)

    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))


class msg_getblocks(object):
    command = b"getblocks"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.locator = core.CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = core.CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = serialize.deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += serialize.ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return ("msg_getblocks(locator=%s hashstop=%064x)" %
                (repr(self.locator), self.hashstop))


class msg_getheaders(object):
    command = b"getheaders"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.locator = core.CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = core.CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = serialize.deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += serialize.ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return ("msg_getheaders(locator=%s hashstop=%064x)" %
                (repr(self.locator), self.hashstop))


class msg_headers(object):
    command = b"headers"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.headers = []

    def deserialize(self, f):
        self.headers = serialize.deser_vector(f, core.CBlock)

    def serialize(self):
        return serialize.ser_vector(self.headers)

    def __repr__(self):
        return "msg_headers(headers=%s)" % (repr(self.headers))


class msg_tx(object):
    command = b"tx"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.tx = core.CTransaction()

    def deserialize(self, f):
        self.tx.deserialize(f)

    def serialize(self):
        return self.tx.serialize()

    def __repr__(self):
        return "msg_tx(tx=%s)" % (repr(self.tx))


class msg_block(object):
    command = b"block"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover
        self.block = core.CBlock()

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self):
        return self.block.serialize()

    def __repr__(self):
        return "msg_block(block=%s)" % (repr(self.block))


class msg_getaddr(object):
    command = b"getaddr"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_getaddr()"

#msg_checkorder
#msg_submitorder
#msg_reply


class Ping(_types.SerializableDict):
    command = b'ping'

    _key_map = {'protover': 'version'}
    _fields = collections.OrderedDict([('nonce', _types.UInt64)])

    def __init__(self, version=coredefs.PROTO_VERSION, nonce=0):
        self['version'] = version
        self['nonce'] = nonce

    @classmethod
    def deserialize(cls, f, version=None):
        version = version if version is not None else coredefs.PROTO_VERSION
        fields = cls._fields.copy()

        if version is not None and version < coredefs.BIP0031_VERSION:
            del fields['nonce']

        return _types.SerializableDict.deserialize.im_func(cls, f, fields,
                                                           version)

    def serialize(self, f, version=None):
        version = version if version is not None else self['version']
        fields = self._fields.copy()

        if version is not None and version < coredefs.BIP0031_VERSION:
            del fields['nonce']

        return _types.SerializableDict.serialize(self, f, fields, version)


class Pong(Ping):
    command = b'pong'


class msg_mempool(object):
    command = b"mempool"

    def __init__(self, protover=coredefs.PROTO_VERSION):
        self.protover = protover

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_mempool()"


MESSAGE_MAP = {
    'version': Version,
    'verack': VerAck,
    'addr': msg_addr,
    'alert': msg_alert,
    'inv': msg_inv,
    'getdata': msg_getdata,
    'getblocks': msg_getblocks,
    'tx': msg_tx,
    'block': msg_block,
    'getaddr': msg_getaddr,
    'ping': Ping,
    'pong': Pong,
    'mempool': msg_mempool
}


def message_read(netmagic, f):
    try:
        recvbuf = f.read(4 + 12 + 4 + 4)
    except IOError:
        return None

    # check magic
    if len(recvbuf) < 4:
        return
    if recvbuf[:4] != netmagic.msg_start:
        raise ValueError("got garbage %s" % repr(recvbuf))

    # check checksum
    if len(recvbuf) < 4 + 12 + 4 + 4:
        return

    # remaining header fields: command, msg length, checksum
    command = recvbuf[4:4+12].split(b"\x00", 1)[0]
    msglen = struct.unpack(b"<i", recvbuf[4+12:4+12+4])[0]
    checksum = recvbuf[4+12+4:4+12+4+4]

    # read message body
    try:
        recvbuf += f.read(msglen)
    except IOError:
        return None

    msg = recvbuf[4+12+4+4:4+12+4+4+msglen]
    th = hashlib.sha256(msg).digest()
    h = hashlib.sha256(th).digest()
    if checksum != h[:4]:
        raise ValueError("got bad checksum %s" % repr(recvbuf))
    recvbuf = recvbuf[4+12+4+4+msglen:]

    if command in MESSAGE_MAP:
        f = cStringIO.StringIO(msg)
        t = MESSAGE_MAP[command]()
        t.deserialize(f)
        return t
    else:
        return None


def message_read(netmagic, f, version=None):
    try:
        msg = Message.deserialize(f, version=version)
    except IOError:
        return

    return msg
