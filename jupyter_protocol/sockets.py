import logging
import os
import pprint
import zmq
from .session import Session

def app_or_module_logger(module_name):
    """
    If a global Application is instantiated, grab its logger.
    Otherwise, get a logger for the module name.
    """
    from traitlets.config import Application
    if Application.initialized():
        return Application.instance().log
    else:
        _logger = logging.getLogger(module_name)
        # Add a NullHandler to silence warnings about not being
        # initialized, per best practice for libraries.
        _logger.addHandler(logging.NullHandler())
        return _logger


# singleton dummy tracker, which will always report as done
DONE = zmq.MessageTracker()


class MessagingBase:
    # Whether to check PID to protect against calls after fork.
    # This check can be disabled if fork-safety is handled elsewhere.
    check_pid = True

    # Threshold (in bytes) beyond which a buffer should be sent without copying.
    copy_threshold = 2 ** 16

    debug = False  # Turn on for debugging output

    def __init__(self, connection_info):
        self.connection_info = connection_info
        #self.manager = manager
        #self.using_heartbeat = use_heartbeat and (manager is not None)
        self.log = app_or_module_logger(__name__)
        self.pid = os.getpid()
        self.context = zmq.Context.instance()
        self.session = Session(key=connection_info['key'].encode('ascii'),
                               signature_scheme=connection_info[
                                   'signature_scheme'])
        self.sockets = {}

    def _make_url(self, channel):
        """Make a ZeroMQ URL for a given channel."""
        transport = self.connection_info['transport']
        ip = self.connection_info['ip']
        port = self.connection_info['%s_port' % channel]

        if transport == 'tcp':
            return "tcp://%s:%i" % (ip, port)
        else:
            return "%s://%s-%s" % (transport, ip, port)

    def _create_bound_socket(self, channel):
        url = self._make_url(channel)
        socket_type = self.socket_types[channel]
        self.log.debug("Binding {} socket to: {}".format(channel, url))
        sock = self.sockets[channel] = self.context.socket(socket_type)
        # set linger to 1s to prevent hangs at exit
        sock.linger = 1000
        if url.startswith('tcp://') and url.endswith(':0'):
            port = sock.bind_to_random_port(url[:-2])
            self.connection_info['%s_port' % channel] = port
        else:
            sock.bind(url)
        return sock

    def recv(self, channel, mode=zmq.NOBLOCK, content=True, copy=True):
        """Receive and unpack a message.

        Parameters
        ----------
        socket : ZMQStream or Socket
            The socket or stream to use in receiving.

        Returns
        -------
        [idents], msg
            [idents] is a list of idents and msg is a nested message dict of
            same format as self.msg returns.
        """
        try:
            raw_msg = self.sockets[channel].recv_multipart(mode, copy=copy)
        except zmq.ZMQError as e:
            if e.errno == zmq.EAGAIN:
                # We can convert EAGAIN to None as we know in this case
                # recv_multipart won't return None.
                return None
            else:
                raise

        print('recvd raw', raw_msg)
        return self.session.deserialize(raw_msg, content=content, copy=copy)

    def send(self, channel, msg, *, track=False):
        """Send a message via stream or socket.

        The message format used by this function internally is as follows:

        [ident1,ident2,...,DELIM,HMAC,p_header,p_parent,p_content,
         buffer1,buffer2,...]

        The serialize/deserialize methods convert the nested message dict into this
        format.

        Parameters
        ----------

        channel : str
            The name of a socket to send the data on (e.g. 'shell')
        msg : Message
            A message object to send
        track : bool
            Whether to track.  Only for use with Sockets, because ZMQStream
            objects cannot track messages.
        """
        if self.check_pid and not os.getpid() == self.pid:
            app_or_module_logger(__name__).warning(
                "WARNING: attempted to send message from fork\n%s", msg
            )
            return

        socket = self.sockets[channel]

        # Check buffers are acceptable
        for idx, buf in enumerate(msg.buffers):
            if isinstance(buf, memoryview):
                view = buf
            else:
                try:
                    # check to see if buf supports the buffer protocol.
                    view = memoryview(buf)
                except TypeError:
                    raise TypeError("Buffer objects must support the buffer protocol.")
            # memoryview.contiguous is new in 3.3,
            # just skip the check on Python 2
            if hasattr(view, 'contiguous') and not view.contiguous:
                # zmq requires memoryviews to be contiguous
                raise ValueError("Buffer %i (%r) is not contiguous" % (idx, buf))

        to_send = self.session.serialize(msg)
        #print(to_send)
        longest = max([ len(s) for s in to_send ])
        copy = (longest < self.copy_threshold)

        if msg.buffers and track and not copy:
            # only really track when we are doing zero-copy buffers
            tracker = socket.send_multipart(to_send, copy=False, track=True)
        else:
            # use dummy tracker, which will be done immediately
            tracker = DONE
            socket.send_multipart(to_send, copy=copy)

        if self.debug:
            pprint.pprint(msg)
            pprint.pprint(to_send)

        msg.tracker = tracker

    def close(self):
        """Close all sockets"""
        for sock in self.sockets.values():
            sock.close()

class ClientMessaging(MessagingBase):
    socket_types = {
        'hb' : zmq.REQ,
        'shell' : zmq.DEALER,
        'iopub' : zmq.SUB,
        'stdin' : zmq.DEALER,
        'control': zmq.DEALER,
        'nanny_events': zmq.SUB,
        'nanny_control': zmq.DEALER,
    }

    def __init__(self, connection_info, use_heartbeat=True):
        super().__init__(connection_info)

        identity = self.session.session_id.encode('utf-8')
        self.iopub_socket = self._create_connected_socket('iopub', identity)
        self.iopub_socket.setsockopt(zmq.SUBSCRIBE, b'')
        self.shell_socket = self._create_connected_socket('shell', identity)
        self.stdin_socket = self._create_connected_socket('stdin', identity)
        self.control_socket = self._create_connected_socket('control', identity)

        if 'nanny_control_port' in connection_info:
            self.nanny_control_socket = self._create_connected_socket('nanny_control', identity)
            self.nanny_events_socket = self._create_connected_socket('nanny_events', identity)

    def _create_connected_socket(self, channel, identity=None):
        """Create a zmq Socket and connect it to the kernel."""
        url = self._make_url(channel)
        socket_type = self.socket_types[channel]
        self.log.debug("Connecting to: %s" % url)
        sock = self.sockets[channel] = self.context.socket(socket_type)
        # set linger to 1s to prevent hangs at exit
        sock.linger = 1000
        if identity:
            sock.identity = identity
        sock.connect(url)
        return sock


class KernelMessaging(MessagingBase):
    socket_types = {
        'hb': zmq.REP,
        'shell': zmq.ROUTER,
        'iopub': zmq.PUB,
        'stdin': zmq.ROUTER,
        'control': zmq.ROUTER,
    }

    def __init__(self, connection_info):
        super().__init__(connection_info)

        self.iopub_socket = self._create_bound_socket('iopub')
        self.shell_socket = self._create_bound_socket('shell')
        self.stdin_socket = self._create_bound_socket('stdin')
        self.control_socket = self._create_bound_socket('control')


class NannyMessaging(MessagingBase):
    socket_types = {
        'nanny_events': zmq.PUB,
        'nanny_control': zmq.ROUTER,
    }

    def __init__(self, connection_info: dict):
        connection_info.setdefault('nanny_events_port', 0)
        connection_info.setdefault('nanny_control_port', 0)
        super().__init__(connection_info)

        self.events_socket = self._create_bound_socket('nanny_events')
        self.control_socket = self._create_bound_socket('nanny_control')
