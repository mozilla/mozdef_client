mozdef_client
=============

mozdef_client is a Python library for sending event information from Python
software to `MozDef`_.

.. _MozDef: https://github.com/jeffbryner/MozDef/

This library performs functions such as message preformatting and validation,
in addition to actually POSTing the events to MozDef using the provided event
collection URL.

The library supports submission of the following MozDef event types, with more
to be added in the future.

- Generic Events
- Compliance Events
- Vulnerability Events

This library was previously known as mozdef_lib, but was renamed for clarity.
The previous version of the library can be found at `mozdef_lib`_.

.. _mozdef_lib: https://github.com/gdestuynder/mozdef_lib/

Installation
------------

As a Python Module
~~~~~~~~~~~~~~~~~~

To install mozdef_client as a module using setup.py, the following
can be used.

.. code::

    make install

Or, to create an RPM/debian package and install that package:

.. code::

   make rpm
   make deb
   rpm -i <package.rpm>
   dpkg -i <package.deb>

As a Submodule
~~~~~~~~~~~~~~

Add to your project with:

.. code::

   git submodule add https://github.com/gdestuynder/mozdef_client
   git commit -a

Python Dependencies
~~~~~~~~~~~~~~~~~~~

* requests_futures for python2 (optional but highly recommended, else messages are synchronous)
* pytz

Usage
-----

An example for submitting generic MozDef events:

.. code::

   # The simple way
   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test message'
   msg.tags = ['tag1', 'tag2']
   msg.details = {'hostname': 'test', 'alert': True}
   msg.send()

   # If you want to also send to syslog
   another_msg.set_send_to_syslog(True)
   another_msg.send()

   # If you only want to send to syslog
   another_msg.set_send_to_syslog(True, only_syslog=True)
   another_msg.send()

Compliance and vulnerability events are submitted by setting the log
attribute of the object to a dict representing the event. An example
for compliance events:

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefCompliance('https://127.0.0.1:8443/compliance')
   msg.log = compliance_msg
   msg.send()

.. note::

   If you can, it is recommended to fill-in details={}, category='' and
   severity='' values, but they are optional.

The library handles validation of the messages prior to submission where
required. In cases where an error occurs, the library will raise a
MozDefError exception.

Syslog Compatibility
~~~~~~~~~~~~~~~~~~~~

If you need syslog capability, as described previously use the set_send_to_syslog()
function to enable this.

The message will be flattened out. Additionally, an attempt will be made to map the severity
field to syslog's priority field if possible (the field name has to match a syslog priority
field name).

Certificate handling
--------------------

During testing with self-signed certificates, it may be useful to disable certificate checking while connecting to MozDef.
It may also just be that you have a custom CA file that you want to point to.

That's how you do all this:

.. code::

    msg.verify_certificate = False # not recommended, security issue.
    msg.verify_certificate = True # uses default certs from /etc/ssl/certs
    msg.verify_certificate = '/etc/path/to/custom/cert'

.. note::

   Disabling certificate checking introduce a security issue and is generally not recommended, specifically for production.

