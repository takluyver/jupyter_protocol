"""Session object for serialising, deserialising and signing messages.
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from binascii import b2a_hex
import hashlib
import hmac
import os
import pprint
import random
import warnings

from zmq.utils import jsonapi

from jupyter_client.jsonutil import extract_dates, date_default
from ipython_genutils.py3compat import (str_to_bytes, unicode_type,)

from jupyter_client.adapter import adapt
from traitlets.log import get_logger
from .messages import Message


#-----------------------------------------------------------------------------
# utility functions
#-----------------------------------------------------------------------------

def squash_unicode(obj):
    """coerce unicode back to bytestrings."""
    if isinstance(obj,dict):
        for key in obj.keys():
            obj[key] = squash_unicode(obj[key])
            if isinstance(key, unicode_type):
                obj[squash_unicode(key)] = obj.pop(key)
    elif isinstance(obj, list):
        for i,v in enumerate(obj):
            obj[i] = squash_unicode(v)
    elif isinstance(obj, unicode_type):
        obj = obj.encode('utf8')
    return obj

#-----------------------------------------------------------------------------
# globals and defaults
#-----------------------------------------------------------------------------

# default values for the thresholds:
MAX_ITEMS = 64
MAX_BYTES = 1024

# ISO8601-ify datetime objects
# allow unicode
# disallow nan, because it's not actually valid JSON
json_packer = lambda obj: jsonapi.dumps(obj, default=date_default,
    ensure_ascii=False, allow_nan=False,
)
json_unpacker = lambda s: jsonapi.loads(s)

DELIM = b"<IDS|MSG>"


def new_id():
    """Generate a new random id.

    Avoids problematic runtime import in stdlib uuid on Python 2.

    Returns
    -------

    id string (16 random bytes as hex-encoded text, chunks separated by '-')
    """
    buf = os.urandom(16)
    return u'-'.join(b2a_hex(x).decode('ascii') for x in (
        buf[:4], buf[4:]
    ))

def new_id_bytes():
    """Return new_id as ascii bytes"""
    return new_id().encode('ascii')

session_aliases = dict(
    ident = 'Session.session',
    user = 'Session.username',
    keyfile = 'Session.keyfile',
)

session_flags  = {
    'secure' : ({'Session' : { 'key' : new_id_bytes(),
                            'keyfile' : '' }},
        """Use HMAC digests for authentication of messages.
        Setting this flag will generate a new UUID to use as the HMAC key.
        """),
    'no-secure' : ({'Session' : { 'key' : b'', 'keyfile' : '' }},
        """Don't authenticate messages."""),
}

def default_secure(cfg):
    """Set the default behavior for a config environment to be secure.

    If Session.key/keyfile have not been set, set Session.key to
    a new random UUID.
    """
    warnings.warn("default_secure is deprecated", DeprecationWarning)
    if 'Session' in cfg:
        if 'key' in cfg.Session or 'keyfile' in cfg.Session:
            return
    # key/keyfile not specified, generate new UUID:
    cfg.Session.key = new_id_bytes()


def extract_header(msg_or_header):
    """Given a message or header, return the header."""
    if not msg_or_header:
        return {}
    try:
        # See if msg_or_header is the entire message.
        h = msg_or_header['header']
    except KeyError:
        try:
            # See if msg_or_header is just the header
            h = msg_or_header['msg_id']
        except KeyError:
            raise
        else:
            h = msg_or_header
    if not isinstance(h, dict):
        h = dict(h)
    return h

class Session(object):
    """Object for handling serialization and sending of messages.

    The Session object handles building messages and sending them
    with ZMQ sockets or ZMQStream objects.  Objects can communicate with each
    other over the network via Session objects, and only need to work with the
    dict-based IPython message spec. The Session will handle
    serialization/deserialization, security, and metadata.

    Sessions support configurable serialization via packer/unpacker traits,
    and signing with HMAC digests via the key/keyfile traits.

    Parameters
    ----------

    key : bytes
        The key used to initialize an HMAC signature.  If unset, messages
        will not be signed or checked.
    signature_scheme : str
        The digest scheme used to construct the message signatures.
        Must have the form 'hmac-HASH' (default: hmac-sha256)
    """
    debug = False   # Turn on for debugging output
    
    # if 0, no adapting to do.
    adapt_version = 0

    # The maximum number of digests to remember.
    # The digest history will be culled when it exceeds this value.
    digest_history_size = 2**16

    def __init__(self, key, signature_scheme='hmac-sha256'):
        self.key = key
        self.signature_scheme = signature_scheme
        self.session_id = new_id()
        self.username = os.environ.get('USER', 'username')
        if self.key:
            hash_name = self.signature_scheme.split('-', 1)[1]
            digest_mod = getattr(hashlib, hash_name)
            self.auth = hmac.HMAC(self.key, digestmod=digest_mod)
        else:
            self.auth = None
            get_logger().warning("Message signing is disabled.  This is insecure and not recommended!")
        self.digest_history = set()

    def clone(self):
        """Create a copy of this Session

        Useful when connecting multiple times to a given kernel.
        This prevents a shared digest_history warning about duplicate digests
        due to multiple connections to IOPub in the same process.
        """
        # make a copy
        new_session = type(self)(key=self.key)
        # fork digest_history
        new_session.digest_history.update(self.digest_history)
        return new_session

    def sign(self, msg_list):
        """Sign a message with HMAC digest. If no auth, return b''.

        Parameters
        ----------
        msg_list : list
            The [p_header,p_parent,p_content] part of the message list.
        """
        if self.auth is None:
            return b''
        h = self.auth.copy()
        for m in msg_list:
            h.update(m)
        return str_to_bytes(h.hexdigest())

    def serialize(self, msg):
        """Serialize the message components to bytes.

        This is roughly the inverse of deserialize. The serialize/deserialize
        methods work with full message lists, whereas pack/unpack work with
        the individual message parts in the message list.

        Parameters
        ----------
        msg : Message
            The message object to be sent

        Returns
        -------
        msg_list : list
            The list of bytes objects to be sent with the format::

                [ident1, ident2, ..., DELIM, HMAC, p_header, p_parent,
                 p_metadata, p_content, buffer1, buffer2, ...]

            In this list, the ``p_*`` entities are the packed or serialized
            versions, so if JSON is used, these are utf8 encoded JSON strings.
        """
        msg_dict = msg.make_dict()

        if self.adapt_version:
            msg_dict = adapt(msg_dict, self.adapt_version)

        header = msg_dict['header'] #.copy()
        header['session'] = self.session_id
        header['username'] = self.username

        real_message = [json_packer(header),
                        json_packer(msg_dict['parent_header']),
                        json_packer(msg_dict['metadata']),
                        json_packer(msg_dict['content']),
        ]

        to_send = msg.idents + [DELIM, self.sign(real_message)] + real_message \
                    + msg.buffers

        return to_send

    def feed_identities(self, msg_list, copy=True):
        """Split the identities from the rest of the message.

        Feed until DELIM is reached, then return the prefix as idents and
        remainder as msg_list. This is easily broken by setting an IDENT to DELIM,
        but that would be silly.

        Parameters
        ----------
        msg_list : a list of zmq.Message or bytes objects
            The message to be split.
        copy : bool
            flag determining whether the arguments are bytes or Messages

        Returns
        -------
        (idents, msg_list) : two lists
            idents will always be a list of bytes, each of which is a ZMQ
            identity. msg_list will be a list of bytes or zmq.Messages of the
            form [HMAC,p_header,p_parent,p_content,buffer1,buffer2,...] and
            should be unpackable/unserializable via self.deserialize at this
            point.
        """
        if copy:
            idx = msg_list.index(DELIM)
            return msg_list[:idx], msg_list[idx+1:]
        else:
            failed = True
            for idx,m in enumerate(msg_list):
                if m.bytes == DELIM:
                    failed = False
                    break
            if failed:
                raise ValueError("DELIM not in msg_list")
            idents, msg_list = msg_list[:idx], msg_list[idx+1:]
            return [m.bytes for m in idents], msg_list

    def _add_digest(self, signature):
        """add a digest to history to protect against replay attacks"""
        if self.digest_history_size == 0:
            # no history, never add digests
            return

        self.digest_history.add(signature)
        if len(self.digest_history) > self.digest_history_size:
            # threshold reached, cull 10%
            self._cull_digest_history()

    def _cull_digest_history(self):
        """cull the digest history

        Removes a randomly selected 10% of the digest history
        """
        current = len(self.digest_history)
        n_to_cull = max(int(current // 10), current - self.digest_history_size)
        if n_to_cull >= current:
            self.digest_history = set()
            return
        to_cull = random.sample(self.digest_history, n_to_cull)
        self.digest_history.difference_update(to_cull)

    def deserialize_msg_parts(self, msg_list, content=True, copy=True):
        """Unserialize a msg_list to a nested message dict.

        This is roughly the inverse of serialize. The serialize/deserialize
        methods work with full message lists, whereas pack/unpack work with
        the individual message parts in the message list.

        Parameters
        ----------
        msg_list : list of bytes or zmq.Message objects
            The list of message parts of the form [HMAC,p_header,p_parent,
            p_metadata,p_content,buffer1,buffer2,...].
        content : bool (True)
            Whether to unpack the content dict (True), or leave it packed
            (False).
        copy : bool (True)
            Whether msg_list contains bytes (True) or the non-copying Message
            objects in each place (False).

        Returns
        -------
        msg : dict
            The nested message dict with top-level keys [header, parent_header,
            content, buffers].  The buffers are returned as memoryviews.
        """
        minlen = 5
        message = {}
        if not copy:
            # pyzmq didn't copy the first parts of the message, so we'll do it
            for i in range(minlen):
                msg_list[i] = msg_list[i].bytes
        if self.auth is not None:
            signature = msg_list[0]
            if not signature:
                raise ValueError("Unsigned Message")
            if signature in self.digest_history:
                raise ValueError("Duplicate Signature: %r" % signature)
            if content:
                # Only store signature if we are unpacking content, don't store if just peeking.
                self._add_digest(signature)
            check = self.sign(msg_list[1:5])
            if not hmac.compare_digest(signature, check):
                raise ValueError("Invalid Signature: %r" % signature)
        if not len(msg_list) >= minlen:
            raise TypeError("malformed message, must have at least %i elements"%minlen)
        header = json_unpacker(msg_list[1])
        message['header'] = extract_dates(header)
        message['parent_header'] = extract_dates(json_unpacker(msg_list[2]))
        message['metadata'] = json_unpacker(msg_list[3])
        if content:
            message['content'] = json_unpacker(msg_list[4])
        else:
            message['content'] = msg_list[4]
        buffers = [memoryview(b) for b in msg_list[5:]]
        if buffers and buffers[0].shape is None:
            # force copy to workaround pyzmq #646
            buffers = [memoryview(b.bytes) for b in msg_list[5:]]
        message['buffers'] = buffers
        if self.debug:
            pprint.pprint(message)
        # adapt to the current version
        return adapt(message)

    def deserialize(self, raw_msg, content=True, copy=True):
        """Deserialize a message from the full wire format.

        This combines feed_identities and deserialize_msg_parts()
        """
        idents, msg_list = self.feed_identities(raw_msg, copy)
        msg_dict = self.deserialize_msg_parts(msg_list, content=content, copy=copy)
        msg_dict['idents'] = idents
        return Message(**msg_dict)
