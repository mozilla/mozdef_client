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
- Asset Hint Events

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

   git submodule add https://github.com/mozilla/mozdef_client
   git commit -a

Python Dependencies
~~~~~~~~~~~~~~~~~~~

- requests_futures (Optional but recommended, otherwise events are synchronous)
- pytz
- boto3 (for AWS support)

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

   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test message'
   msg.tags = ['tag1', 'tag2']
   msg.details = {'hostname': 'test', 'alert': True}
   msg.set_send_to_syslog(True)
   msg.send()

   # Or optionally, if you only want to send to syslog.
   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test message'
   msg.tags = ['tag1', 'tag2']
   msg.details = {'hostname': 'test', 'alert': True}
   msg.set_send_to_syslog(True, only_syslog=True)
   msg.send()


And here's how you send to an Sqs queue in AWS. Note that the URL is ignored for compatibility purposes.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test message'
   msg.tags = ['tag1', 'tag2']
   msg.details = {'hostname': 'test', 'alert': True}
   msg.set_send_to_sqs(True)
   msg.set_sqs_queue_name('my_queue')
   msg.set_sqs_region('us-west-1')
   msg.set_sqs_aws_account_id('012345678901') # Not required if the SQS queue is in the local AWS account
   # Note that unlike syslog this will NEVER send to MozDef HTTP (URL is ignored)
   msg.send()

Compliance events (MozDefCompliance()) are sent the same way as
generic events. Typically details and tags will be set. Details must
adhere to the compliance event format or validation will fail.

Vulnerability events are submitted by setting the log
attribute of the object to a dict representing the event. This dict is
converted in it's entirety to the event. The following is an example for
vulnerability events.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefVulnerability('https://127.0.0.1:8443/compliance')
   msg.log = vuln_msg
   msg.send()

Hint events operate like generic events, but set some default fields
for you.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefAssetHint('https://127.0.0.1:8443/events')
   msg.summary = 'new host detected'
   msg.details = {'hostname': 'test'}
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

Notes on Syslog Compatibility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using the syslog compatibility mode, the JSON message is flattened into
a single line. The severity associated with the message will also be converted
into a syslog severity when the message is sent to syslog.

.. code::

   import mozdef_client
   msg = mozdef_client.MozDefEvent('https://127.0.0.1:8443/events')
   msg.summary = 'a test event'
   msg.tags = ['generic', 'test']
   msg.details = {'one': 1, 'two': 'two'}
   msg.set_severity(MozDefEvent.SEVERITY_CRIT)
   msg.set_send_to_syslog(True, only_syslog=True)
   msg.send()

::

   Mar  6 09:05:48 hostname mozdef_client.py: {"category": "event", "processid": 8095, "severity": "CRIT", "tags": ["generic", "test"], "timestamp": "2015-03-06T15:05:48.226939+00:00", "hostname": "hostname", "summary": "a test event", "processname": "mozdef_client.py", "details": {"two": "two", "one": 1}}

Certificate Handling
--------------------

During testing with self-signed certificates, it may be useful to not validate
certificates. Certificate validation should be enabled in production; this can
be done by calling the set_verify() method on the event with a boolean argument.

Certificates are validated using the default certificate path on the system. If
you want to specify a certificate to use, pass it with the set_verify_path()
method on the event object before calling send().

