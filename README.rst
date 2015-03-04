mozdef_client
=============

Python client lib for `MozDef clients <https://github.com/jeffbryner/MozDef/>`_.

This library is used to send events to MozDef. Currently standard events,
vulnerability events, and compliance events are supported by the library.

This library superseeds mozdef_lib; it was renamed in favor of a less
confusing name.

Install
--------
As a Python Module
~~~~~~~~~~~~~~~~~~

Manually:

.. code::

    make install

As an rpm/deb package

.. code::

   make rpm
   make deb
   rpm -i <package.rpm>
   dpkg -i <package.deb>

From the Code/Integrate in my Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add to your project with:

.. code::

   git submodule add https://github.com/gdestuynder/mozdef_client
   git commit -a

Python dependencies
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

   # If you want to send to syslog
   another_msg.set_send_to_syslog(True)
   another_msg.send()

   # If you only want to send to syslog
   another_msg.set_send_to_syslog(True, only_syslog=True)
   another_msg.send()

.. note::

   If you can, it is recommended to fill-in details={}, category='' and
   severity='' values, but they are optional

Syslog compatibility
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

