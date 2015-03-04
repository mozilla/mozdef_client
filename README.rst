mozdef_client
=============

Python client lib for `MozDef clients <https://github.com/jeffbryner/MozDef/>`_.

This library is used to send events to MozDef. Currently standard events,
vulnerability events, and compliance events are supported by the library.

This library superseeds mozdef_lib; it was renamed in favor of a less
confusing name.

Install
--------
As A Python Module
~~~~~~~~~~~~~~~~~~

Manually:

.. code::

    make install

As a rpm/deb package

.. code::

   make rpm
   make deb
   rpm -i <package.rpm>
   dpkg -i <package.deb>

From the code/integrate in my code
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

.. code::
   # The simple way
   import mozdef_client
   msg = mozdef_client.MozDefMsg('https://127.0.0.1:8443/events', tags=['openvpn', 'duosecurity'])
   msg.send('User logged in', details={'username': user})

   # Some more possibilities
   another_msg = mozdef_client.MozDefMsg('https://127.0.0.1:8443/events', tags=['bro'])
   another_msg.send('knock knock')
   another_msg.log['some-internal-attribute'] = 'smth'
   another_msg.send('who\'s there?')

   # if you also want to send to syslog - this will flatten out the msg for syslog usage:
   another_msg.sendToSyslog = True
   another_msg.send("hi")
   # if you do NOT want to send to MozDef (only makes complete sense if you send to syslog as per above option):
   another_msg.syslogOnly = True
   another_msg.send('This only goes to syslog, or nowhere if sendToSyslog is not True')
   # etc.

.. note::

   If you can, it is recommended to fill-in details={}, category='' and severity='' even thus those are optional.

Syslog compatibility
~~~~~~~~~~~~~~~~~~~~

Should you be needing Syslog compatibility (for example to stay compatible with non-MozDef setups without having to
handle the conversion to syslog on your own) just set sendToSyslog to True for your message.

The message will be flattened out and fields that syslog already provide will be stripped. Additionally, an attempt will
be made to map the severity field to syslog's priority field if possible (the field name has to match a syslog priority
field name).

Example:

.. code::

    #JSON/MozDef output
    {
        "category": "event",
        "details": {},
        "hostname": "kang-vp",
        "processid": 16347,
        "processname": "mozdef_client.py",
        "severity": "INFO",
        "summary": "test msg",
        "tags": [],
        "timestamp": "2014-05-13T14:59:54.093572+00:00"
    }
    [...]

    #Syslog output
    May 13 14:59:54 kang-vp mozdef_client.py[16347]: details: {} tags: [] category: event summary: test syslog msg
    May 13 14:59:54 kang-vp mozdef_client.py[16347]: details: {'uid': 0, 'username': 'kang'} tags: ['bro', 'auth'] category:
    authentication summary: new test msg
    May 13 14:59:54 kang-vp mozdef_client.py[16347]: details: {} tags: [] category: event summary: another test msg


MozDef Event message structure
-------------------------------
These are also the 'internal attributes' which you can modify.

.. code::

    {
        "category": "authentication",
            "details": {
                "uid": 0,
                "username": "kang"
            },
            "hostname": "blah.private.scl3.mozilla.com",
            "processid": 14619,
            "processname": "./mozdef_client.py",
            "severity": "CRITICAL",
            "summary": "new test msg",
            "tags": [
                "bro",
            "auth"
                ],
            "timestamp": "2014-03-18T23:20:31.013344+00:00"
    }

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

   Disabling certificate checking introduce a security issue and is generally not recommended, specially for production.
