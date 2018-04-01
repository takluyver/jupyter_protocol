from binascii import b2a_hex
import os
from datetime import timezone, datetime
from ._version import protocol_version

def utcnow():
    """Return timezone-aware UTC timestamp"""
    return datetime.utcnow().replace(tzinfo=timezone.utc)

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

def new_header(msg_type):
    """Create a new message header

    username and session are set later when the message is serialised.
    """
    return {
        'date': utcnow(),
        'msg_type': msg_type,
        'msg_id': new_id(),
        'username': '',
        'session': '',
        'version': protocol_version,
    }

class Message:
    tracker = None  # Set when sending

    def __init__(self, content, header, parent_header=None, metadata=None,
                 idents=None, buffers=None):
        self.content = content
        self.header = header
        self.parent_header = parent_header or {}
        self.metadata = metadata or {}
        self.idents = idents or []
        self.buffers = buffers or []

    @classmethod
    def from_type(cls, msg_type, content, parent_msg=None, metadata=None):
        if parent_msg is None:
            parent_header = {}
            idents = []
        else:
            parent_header = parent_msg.header
            idents = parent_msg.idents
        return cls(content=content, header=new_header(msg_type),
                   parent_header=parent_header, metadata=metadata, idents=idents)

    def make_dict(self):
        return {
            'content': self.content,
            'header': self.header,
            'parent_header': self.parent_header,
            'metadata': self.metadata,
        }

    def __repr__(self):
        args = [repr(self.content), repr(self.header)]
        if self.parent_header:
            args.append('parent_header=%r' % self.parent_header)
        if self.metadata:
            args.append('metadata=%r' % self.parent_header)
        if self.idents:
            args.append('idents=%r' % self.idents)
        if self.buffers:
            args.append('buffers=%r' % self.buffers)
        return "Message(%s)" % ', '.join(args)
