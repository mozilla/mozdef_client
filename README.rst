mozdef_lib
==========

Python lib for `MozDef clients <https://github.com/jeffbryner/MozDef/>`_.

Install
--------
Add to your project with:

.. code::

   git submodule add https://github.com/gdestuynder/mozdef_lib mozdef
   git commit -a

Make sure you've got the following Python modules, too:

* requests_futures
* pytz

Usage
-----

.. code::
   # The simple way
   import mozdef
   msg = mozdef.MozDefMsg('https://127.0.0.1:8443/events', tags['openvpn', 'duosecurity'])
   msg.send('User logged in', details={'username': user})

   # Some more possibilities
   another_msg = mozdef.MozDefMsg('https://127.0.0.1:8443/events', tags=['bro'])
   another_msg.send('knock knock')
   another_msg.log['some-internal-attribute'] = 'smth'
   another_msg.send('who's there?')
   # etc.

.. note::

   If you can, it is recommended to fill-in details={}, category='' and severity='' even thus those are optional.

MozDef message structure
------------------------
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
            "processname": "./mozdef.py",
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
