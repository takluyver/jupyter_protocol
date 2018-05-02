# Jupyter Protocol

This is an experimental implementation of the [Jupyter protocol][],
to be used by both clients and kernels.

[Jupyter protocol]: https://jupyter-client.readthedocs.io/en/latest/messaging.html

A few notes on the pieces and ideas:

* The `messages` module contains many functions for constructing messages of
  different types. The idea is to encapsulate as much of the message structure
  as possible here, to reduce the ambiguity where a kernel written in Python
  speaks a protocol defined partly by a library and partly by the kernel's
  own implementation.
* A Session handles (de)serialisation. Its scope is reduced from the Session
  class in `jupyter_client`, because it no longer handles sending and receiving.
* The messaging classes in `jupyter_protocol.sockets` handle setting up ZMQ
  sockets, sending and receiving messages. There is one for each piece that
  communicates: `KernelMessaging`, `ClientMessaging`, `NannyMessaging`.
* I try to consistently represent unserialised messages as `Message` objects.
  These objects include the idents and buffers that we previously handled
  separately from the main JSON-able message parts.
  The `adapter` module is currently an exception (it works with dicts).
* The message schemas from `jupyter_kernel_test` are going to come here too,
  but this hasn't happened yet.
