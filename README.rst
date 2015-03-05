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

- requests_futures (Optional but recommended, otherwise events are synchronous)
- pytz

Usage
-----

The following is an example for submitting generic MozDef events.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test message'
   msg.tags = ['tag1', 'tag2']
   msg.details = {'hostname': 'test', 'alert': True}
   msg.send()

It is also possible to additionally send the message to syslog, in this case
it will be flattened.

.. code::

   msg.set_send_to_syslog(True)
   msg.send()

   # Or optionally, if you only want to send to syslog.
   msg.set_send_to_syslog(True, only_syslog=True)
   msg.send()

Compliance and vulnerability events are submitted by setting the log
attribute of the object to a dict representing the event. This dict is
converted in it's entirety to the event. The following is an example for
compliance events.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefCompliance('https://127.0.0.1:8443/compliance')
   msg.log = compliance_msg
   msg.send()

With generic event messages, the summary field is the only mandatory field
that must be set on the event before submission. Compliance and vulnerability
events have a specific format and require a number of default fields to exist
before submission. The validation functions in the library will raise a
MozDefError exception if an error condition occurs (such as submission of an
invalid message).

With a generic event message, the members of the object you will generally
modify before calling send() include:

* .details (dict)
* .summary (string)
* .tags (list)

Also, for event messages the set_severity() and set_category() methods can be
used to change the message severity and category. The category argument is a
string value, the severity can be one of the following.

* MozDefEvent.SEVERITY_INFO
* MozDefEvent.SEVERITY_WARNING
* MozDefEvent.SEVERITY_CRITICAL
* MozDefEvent.SEVERITY_ERROR
* MozDefEvent.SEVERITY_DEBUG

With compliance and vulnerability events, you will generally operate on the
.log member of the object, which is a dict.

Notes on Syslog Compatability
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using the syslog compatability mode, the JSON message is flattened into
a single line. The severity associated with the message will also be converted
into a syslog severity when the message is sent to syslog.

Certificate Handling
--------------------

During testing with self-signed certificates, it may be useful to not validate
certificates. Certificate validation should be enabled in production; this can
be done by calling the set_verify() method on the event with a boolean argument.

Certificates are validated using the default certificate path on the system. If
you want to specify a certificate to use, pass it with the set_verify_path()
method on the event object before calling send().

