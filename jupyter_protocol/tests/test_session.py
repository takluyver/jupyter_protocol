"""test building messages with Session"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import hmac
import os
import sys
import uuid
from datetime import datetime
try:
    from unittest import mock
except ImportError:
    import mock

import pytest

import zmq

from zmq.tests import BaseZMQTestCase

from jupyter_protocol import session as ss
from jupyter_protocol import jsonutil
from jupyter_protocol.messages import utcnow, Message, new_header

from ipython_genutils.py3compat import string_types

def _bad_packer(obj):
    raise TypeError("I don't work")

def _bad_unpacker(bytes):
    raise TypeError("I don't work either")

class SessionTestCase(BaseZMQTestCase):

    def setUp(self):
        BaseZMQTestCase.setUp(self)
        self.session = ss.Session(key=b'')


@pytest.fixture
def no_copy_threshold():
    """Disable zero-copy optimizations in pyzmq >= 17"""
    with mock.patch.object(zmq, 'COPY_THRESHOLD', 1):
        yield


@pytest.mark.usefixtures('no_copy_threshold')
class TestSession(SessionTestCase):

    def test_serialize(self):
        msg = Message.from_type('execute', content=dict(a=10, b=1.1))
        msg.idents = [b'foo']
        msg_list = self.session.serialize(msg)
        new_msg = self.session.deserialize(msg_list)
        assert new_msg.idents == [b'foo']
        assert new_msg.header == msg.header
        assert new_msg.content == msg.content
        assert new_msg.parent_header == msg.parent_header
        assert new_msg.metadata == msg.metadata
        # ensure floats don't come out as Decimal:
        assert type(new_msg.content['b']) == type(new_msg.content['b'])

    def test_unique_msg_ids(self):
        """test that messages receive unique ids"""
        ids = set()
        for i in range(2**12):
            h = new_header('test')
            msg_id = h['msg_id']
            self.assertTrue(msg_id not in ids)
            ids.add(msg_id)

    def test_zero_digest_history(self):
        session = ss.Session(key=b'')
        session.digest_history_size = 0
        for i in range(11):
            session._add_digest(uuid.uuid4().bytes)
        self.assertEqual(len(session.digest_history), 0)

    def test_cull_digest_history(self):
        session = ss.Session(key=b'')
        session.digest_history_size = 100
        for i in range(100):
            session._add_digest(uuid.uuid4().bytes)
        assert len(session.digest_history) == 100
        session._add_digest(uuid.uuid4().bytes)
        assert len(session.digest_history) == 91
        for i in range(9):
            session._add_digest(uuid.uuid4().bytes)
        assert len(session.digest_history) == 100
        session._add_digest(uuid.uuid4().bytes)
        assert len(session.digest_history) == 91

    def test_datetimes(self):
        content = dict(t=utcnow())
        metadata = dict(t=utcnow())
        p = Message.from_type('msg', {})
        msg = Message.from_type('msg', content, metadata=metadata, parent_msg=p)
        smsg = self.session.serialize(msg)
        msg2 = self.session.deserialize(smsg)
        assert isinstance(msg2.header['date'], datetime)
        assert msg.header == msg2.header
        assert msg.parent_header == msg2.parent_header
        assert msg.parent_header == msg2.parent_header
        assert isinstance(msg.content['t'], datetime)
        assert isinstance(msg.metadata['t'], datetime)
        assert isinstance(msg2.content['t'], string_types)
        assert isinstance(msg2.metadata['t'], string_types)
        assert msg.content == jsonutil.extract_dates(msg2.content)
        assert msg.metadata == jsonutil.extract_dates(msg2.metadata)
    
    def test_clone(self):
        s = self.session
        s._add_digest('initial')
        s2 = s.clone()
        assert s2.digest_history == s.digest_history
        assert s2.digest_history is not s.digest_history
        digest = 'abcdef'
        s._add_digest(digest)
        assert digest in s.digest_history
        assert digest not in s2.digest_history
