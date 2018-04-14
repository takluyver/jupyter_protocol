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


def validate_string_dict(dct):
    """Validate that the input is a dict with string keys and values.

    Raises ValueError if not."""
    for k, v in dct.items():
        if not isinstance(k, str):
            raise ValueError('key %r in dict must be a string' % k)
        if not isinstance(v, str):
            raise ValueError('value %r in dict must be a string' % v)

def execute_request(code, silent=False, store_history=True,
            user_expressions=None, allow_stdin=False, stop_on_error=True):
    """Construct an execute_request message.

    Parameters
    ----------
    code : str
        A string of code in the kernel's language.

    silent : bool, optional (default False)
        If set, the kernel will execute the code as quietly possible, and
        will force store_history to be False.

    store_history : bool, optional (default True)
        If set, the kernel will store command history.  This is forced
        to be False if silent is True.

    user_expressions : dict, optional
        A dict mapping names to expressions to be evaluated in the user's
        dict. The expression values are returned as strings formatted using
        :func:`repr`.

    allow_stdin : bool, optional (default self.allow_stdin)
        Flag for whether the kernel can send stdin requests to frontends.

        Some frontends (e.g. the Notebook) do not support stdin requests.
        If raw_input is called from code executed from such a frontend, a
        StdinNotImplementedError will be raised.

    stop_on_error: bool, optional (default True)
        Flag whether to abort the execution queue, if an exception is encountered.
    """
    if user_expressions is None:
        user_expressions = {}

    # Don't waste network traffic if inputs are invalid
    if not isinstance(code, str):
        raise ValueError('code %r must be a string' % code)
    validate_string_dict(user_expressions)

    content = dict(code=code, silent=silent, store_history=store_history,
                   user_expressions=user_expressions,
                   allow_stdin=allow_stdin, stop_on_error=stop_on_error
                   )
    return Message.from_type('execute_request', content)

def shell_reply_error(reply_type, ename, evalue, traceback, *, parent=None):
    """Make a reply to a shell message on an error.

    This has the same structure for different message types. reply_type should
    be e.g. 'execute_reply'.
    """
    return Message.from_type(reply_type, {
        'status': 'error',
        'ename': ename, 'evalue': evalue, 'traceback': traceback,
    }, parent_msg=parent)

def execute_reply(execution_count, payloads=None, user_expressions=None, *, parent=None):
    """Make an execute_reply for successful execution."""
    if payloads is None:
        payloads = []
    if user_expressions is None:
        user_expressions = {}
    return Message.from_type('execute_reply', {
        'status': 'ok',
        'execution_count': execution_count,
        'payloads': payloads,
        'user_expressions': user_expressions,
    }, parent_msg=parent)

def complete_request(code, cursor_pos=None):
    """Make a complete_request message.

    Parameters
    ----------
    code : str
        The context in which completion is requested.
        Can be anything between a variable name and an entire cell.
    cursor_pos : int, optional
        The position of the cursor in the block of code where the completion was requested.
        Default: ``len(code)``
    """
    if cursor_pos is None:
        cursor_pos = len(code)
    content = dict(code=code, cursor_pos=cursor_pos)
    return Message.from_type('complete_request', content)

def complete_reply(matches, cursor_start, cursor_end, metadata=None, *, parent=None):
    """Make a complete_reply for successful completion."""
    if metadata is None:
        metadata = {}
    return Message.from_type('complete_reply', {
        'status': 'ok',
        'matches': matches,
        'cursor_start': cursor_start,
        'cursor_end': cursor_end,
        'metadata': metadata,
    }, parent_msg=parent)

def inspect_request(code, cursor_pos=None, detail_level=0):
    """Make an inspect_request message.

    Get metadata information about an object in the kernel's namespace.

    It is up to the kernel to determine the appropriate object to inspect.

    Parameters
    ----------
    code : str
        The context in which info is requested.
        Can be anything between a variable name and an entire cell.
    cursor_pos : int, optional
        The position of the cursor in the block of code where the info was requested.
        Default: ``len(code)``
    detail_level : int, optional
        The level of detail for the introspection (0-2)
    """
    if cursor_pos is None:
        cursor_pos = len(code)
    return Message.from_type('inspect_request', {
        'code': code,
        'cursor_pos': cursor_pos,
        'detail_level': detail_level,
    })

def inspect_reply(found: bool, data: dict, metadata=None, *, parent=None):
    """Make an inspect_reply for successful introspection."""
    if not found:
        assert not data
    if metadata is None:
        metadata = {}
    return Message.from_type('inspect_reply', {
        'found': found,
        'data': data,
        'metadata': metadata
    }, parent_msg=parent)

def history_request(raw=True, output=False, hist_access_type='range',
                    session=0, start=0, stop=None, n=0, pattern=''):
    """Get entries from the kernel's history list.

    Parameters
    ----------
    raw : bool
        If True, return the raw input.
    output : bool
        If True, then return the output as well.
    hist_access_type : str
        'range' (fill in session, start and stop params), 'tail' (fill in n)
         or 'search' (fill in pattern param).

    session : int
        For a range request, the session from which to get lines. Session
        numbers are positive integers; negative ones count back from the
        current session.
    start : int
        The first line number of a history range.
    stop : int
        The final (excluded) line number of a history range.

    n : int
        The number of lines of history to get for a tail request.

    pattern : str
        The glob-syntax pattern for a search request.
    """
    content = {
        'hist_access_type': hist_access_type,
        'raw': raw,
        'output': output,
    }
    if hist_access_type == 'range':
        content.update({
            'session': session,
            'start': start,
            'stop': stop,
        })
    elif hist_access_type == 'tail':
        assert n > 0
        content['n'] = n
    elif hist_access_type == 'search':
        assert pattern != ''
        content['pattern'] = pattern
    else:
        ValueError("Unknown hist_access_type %r" % hist_access_type)

    return Message.from_type('history_request', content)

def kernel_info_request():
    """Make a kernel_info_request message.
    """
    return Message.from_type('kernel_info_request', {})

def kernel_info_reply(implementation: str, implementation_version: str,
                      language_info: dict, banner='', help_links=None,
                      *, parent=None):
    """Make a kernel_info_reply message"""
    if help_links is None:
        help_links = []
    return Message.from_type('kernel_info_reply', {
        'status': 'ok',
        'protocol_version': protocol_version,
        'implementation': implementation,
        'implementation_version': implementation_version,
        'language_info': language_info,
        'banner': banner,
        'help_links': help_links
    }, parent_msg=parent)

def comm_info_request(target_name=None):
    """Make a comm_info_request message.
    """
    if target_name is None:
        content = {}
    else:
        content = dict(target_name=target_name)
    return Message.from_type('comm_info_request', content)

def comm_info_reply(comms: dict, *, parent=None):
    """Make a comm_info_reply message."""
    return Message.from_type('comm_info_reply', {
        'status': 'ok', 'comms': comms,
    }, parent_msg=parent)

def shutdown_request(restart=False):
    """Make a shutdown_request message.

    Upon receipt of the (empty) reply, client code can safely assume that
    the kernel has shut down and it's safe to forcefully terminate it if
    it's still alive.

    The kernel will send the reply via a function registered with Python's
    atexit module, ensuring it's truly done as the kernel is done with all
    normal operation.
    """
    # Send quit message to kernel. Once we implement kernel-side setattr,
    # this should probably be done that way, but for now this will do.
    return Message.from_type('shutdown_request', {'restart': restart})

def shutdown_reply(restart=False, *, parent=None):
    """Make a shutdown_reply message."""
    return Message.from_type('shutdown_reply', {
        'status': 'ok', 'restart': restart,
    }, parent_msg=parent)

def is_complete_request(code):
    """Make an is_complete_request message.

    This is used to ask the kernel if some code is complete & ready to execute.
    """
    return Message.from_type('is_complete_request', {'code': code})

def is_complete_reply(status, indent=0, *, parent=None):
    """Make an is_complete_reply message."""
    return Message.from_type('is_complete_reply', {
        'status': status, 'indent': indent,
    }, parent_msg=parent)

def interrupt_request():
    """Make an is_complete_request message"""
    return Message.from_type("interrupt_request", content={})

def interrupt_reply(*, parent=None):
    return Message.from_type("interrupt_reply", content={'status': 'ok'},
                             parent_msg=parent)

def input_request(prompt: str, password=False, *, parent=None):
    return Message.from_type("input_request", content={
        'prompt': prompt, 'password': password
    }, parent_msg=parent)

def input_reply(string: str, *, parent=None):
    """Make an input_reply message, to send a string of input to the kernel.

    This should only be called in response to the kernel sending an
    ``input_request`` message on the stdin channel.
    """
    content = dict(value=string)
    return Message.from_type('input_reply', content, parent_msg=parent)

# IOPub messages ---------------

def stream(text, stream_name='stdout', *, parent=None):
    assert stream_name in {'stdout', 'stderr'}
    return Message.from_type('stream', {
        'name': stream_name, 'text': text,
    }, parent_msg=parent)

def display_data(data: dict, metadata: dict =None, transient: dict =None, *, parent=None):
    if metadata is None:
        metadata = {}
    if transient is None:
        transient = {}
    return Message.from_type('display_data', {
        'data': data, 'metadata': metadata, 'transient': transient,
    }, parent_msg=parent)

def update_display_data(data: dict, metadata: dict =None, transient: dict =None, *, parent=None):
    if metadata is None:
        metadata = {}
    if transient is None:
        transient = {}
    return Message.from_type('update_display_data', {
        'data': data, 'metadata': metadata, 'transient': transient,
    }, parent_msg=parent)

def execute_result(execution_count: int, data: dict, metadata: dict =None,
                   transient: dict =None, *, parent=None):
    if metadata is None:
        metadata = {}
    if transient is None:
        transient = {}
    return Message.from_type('execute_result', {
        'execution_count': execution_count,
        'data': data, 'metadata': metadata, 'transient': transient,
    }, parent_msg=parent)

def execute_input(code: str, execution_count: int, *, parent=None):
    return Message.from_type('execute_input', {
        'code': code, 'execution_count': execution_count,
    }, parent_msg=parent)

def error(ename, evalue, traceback, *, parent=None):
    return Message.from_type('error', {
        'ename': ename, 'evalue': evalue, 'traceback': traceback,
    }, parent_msg=parent)

def kernel_status(status: str, *, parent=None):
    assert status in {'busy', 'idle', 'starting'}
    return Message.from_type('status', {
        'execution_state': status,
    }, parent_msg=parent)

def clear_output(wait: bool, *, parent=None):
    return Message.from_type('clear_output',  {'wait': wait}, parent_msg=parent)
