from jupyter_protocol.messages import *

def test_create_simple():
    msg = Message.from_type('kernel_info_request', {})
    assert isinstance(msg.content, dict)
    assert isinstance(msg.metadata, dict)
    assert isinstance(msg.header, dict)
    assert isinstance(msg.parent_header, dict)
    assert isinstance(msg.header['msg_id'], str)
    assert msg.header['msg_type'] == 'kernel_info_request'
