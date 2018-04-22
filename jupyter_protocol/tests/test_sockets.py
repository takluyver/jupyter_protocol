import os
import pytest
import zmq
from zmq.eventloop.zmqstream import ZMQStream
from zmq.tests import BaseZMQTestCase

from jupyter_protocol.messages import Message
from jupyter_protocol.session import Session
from jupyter_protocol.sockets import MessagingBase, DONE

def _messaging_w_socket_pair(a, b):
    messaging = MessagingBase({
        'key': '',
        'signature_scheme': 'hmac-sha256',
    })
    messaging.sockets['A'] = a
    messaging.sockets['B'] = b
    return messaging

def test_send():
    ctx = zmq.Context.instance()
    A = ctx.socket(zmq.PAIR)
    B = ctx.socket(zmq.PAIR)
    A.bind("inproc://test")
    B.connect("inproc://test")

    messaging = _messaging_w_socket_pair(A, B)

    msg = Message.from_type('test_xmpl', dict(a=10))
    msg.idents = [b'foo']
    msg.buffers = [b'bar']

    messaging.send('A', msg)

    new_msg = messaging.recv('B')
    assert new_msg.idents[0] == b'foo'
    assert new_msg.header == msg.header
    assert new_msg.content == msg.content
    assert new_msg.parent_header == msg.parent_header
    assert new_msg.metadata == msg.metadata
    assert new_msg.buffers == msg.buffers

    # buffers must support the buffer protocol
    msg.buffers = [1]
    with pytest.raises(TypeError):
        messaging.send('A', msg)

    # buffers must be contiguous
    buf = memoryview(os.urandom(16))
    msg.buffers = [buf[::2]]
    with pytest.raises(ValueError):
        messaging.send('A', msg)

    A.close()
    B.close()
    ctx.term()

# def test_send_raw():
#     ctx = zmq.Context.instance()
#     A = ctx.socket(zmq.PAIR)
#     B = ctx.socket(zmq.PAIR)
#     A.bind("inproc://test")
#     B.connect("inproc://test")
#
#     msg = self.session.msg('execute', content=dict(a=10))
#     msg_list = [self.session.pack(msg[part]) for part in
#                 ['header', 'parent_header', 'metadata', 'content']]
#     self.session.send_raw(A, msg_list, ident=b'foo')
#
#     ident, new_msg_list = self.session.feed_identities(B.recv_multipart())
#     new_msg = self.session.deserialize(new_msg_list)
#     self.assertEqual(ident[0], b'foo')
#     self.assertEqual(new_msg['msg_type'],msg['msg_type'])
#     self.assertEqual(new_msg['header'],msg['header'])
#     self.assertEqual(new_msg['parent_header'],msg['parent_header'])
#     self.assertEqual(new_msg['content'],msg['content'])
#     self.assertEqual(new_msg['metadata'],msg['metadata'])
#
#     A.close()
#     B.close()
#     ctx.term()

class SocketsTestCase(BaseZMQTestCase):
    def test_tracking(self):
        """test tracking messages"""
        a,b = self.create_bound_pair(zmq.PAIR, zmq.PAIR)
        messaging = _messaging_w_socket_pair(a, b)
        messaging.copy_threshold = 1
        stream = ZMQStream(a)
        msg = Message.from_type('test_xmpl', {})
        messaging.send('A', msg, track=False)
        assert msg.tracker is DONE

        messaging.send('A', msg, track=True)
        assert isinstance(msg.tracker, zmq.MessageTracker)

        msg2 = Message.from_type('test_xmpl', {})
        msg2.buffers = [zmq.Frame(b'hi there', track=True, copy=False)]
        messaging.send('A', msg2, track=True)
        t = msg2.tracker
        assert isinstance(t, zmq.MessageTracker)
        assert t is not DONE
        with pytest.raises(zmq.NotDone):
            t.wait(.1)
        del msg2
        t.wait(1)
