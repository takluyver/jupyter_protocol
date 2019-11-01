.. _kernels:

==========================
Making kernels for Jupyter
==========================

A 'kernel' is a program that runs and introspects the user's code. IPython
includes a kernel for Python code, and people have written kernels for
`several other languages <https://github.com/jupyter/jupyter/wiki/Jupyter-kernels>`_.

When Jupyter starts a kernel, it passes it a connection file. This specifies
how to set up communications with the frontend.

There are two options for writing a kernel:

1. You can reuse the IPython kernel machinery to handle the communications, and
   just describe how to execute your code. This is much simpler if the target
   language can be driven from Python. See :doc:`wrapperkernels` for details.
2. You can implement the kernel machinery in your target language. This is more
   work initially, but the people using your kernel might be more likely to
   contribute to it if it's in the language they know.

.. _connection_files:

Connection files
================

Your kernel will be given the path to a connection file when it starts (see
:ref:`kernelspecs` for how to specify the command line arguments for your kernel).
This file, which is accessible only to the current user, will contain a JSON
dictionary looking something like this::

    {
      "control_port": 50160,
      "shell_port": 57503,
      "transport": "tcp",
      "signature_scheme": "hmac-sha256",
      "stdin_port": 52597,
      "hb_port": 42540,
      "ip": "127.0.0.1",
      "iopub_port": 40885,
      "key": "a0436f6c-1916-498b-8eb9-e81ab9368e84"
    }

The ``transport``, ``ip`` and five ``_port`` fields specify five ports which the
kernel should bind to using `ZeroMQ <http://zeromq.org/>`_. For instance, the
address of the shell socket in the example above would be::

    tcp://127.0.0.1:57503

New ports are chosen at random for each kernel started.

``signature_scheme`` and ``key`` are used to cryptographically sign messages, so
that other users on the system can't send code to run in this kernel. See
:ref:`wire_protocol` for the details of how this signature is calculated.

Handling messages
=================

After reading the connection file and binding to the necessary sockets, the
kernel should go into an event loop, listening on the hb (heartbeat), control
and shell sockets.

:ref:`Heartbeat <kernel_heartbeat>` messages should be echoed back immediately
on the same socket - the frontend uses this to check that the kernel is still
alive.

Messages on the control and shell sockets should be parsed, and their signature
validated. See :ref:`wire_protocol` for how to do this.

The kernel will send messages on the iopub socket to display output, and on the
stdin socket to prompt the user for textual input.

.. seealso::

   :doc:`messaging`
     Details of the different sockets and the messages that come over them

   `Creating Language Kernels for IPython <http://andrew.gibiansky.com/blog/ipython/ipython-kernels/>`_
     A blog post by the author of `IHaskell <https://github.com/gibiansky/IHaskell>`_,
     a Haskell kernel

   `simple_kernel <https://github.com/dsblank/simple_kernel>`_
     A simple example implementation of the kernel machinery in Python

.. _kernelspecs:

Kernel specs
============

A kernel typically identifies itself to an IPython-compatible application by creating a directory, 
the name of which is used as an identifier for the kernel.  The contents of this directory
is what is referred to as the *kernel specfication*.  For more information on kernel specs
and other ways kernels are identified, please refer to the `Jupyter Kernel Management documentation 
<https://jupyter-kernel-mgmt.readthedocs.io/en/latest/index.html>`_.
