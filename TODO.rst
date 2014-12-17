TODO
----

- Could report to syslog when fire_and_forget_mode is True and we fail
- Could make requests threaded to emulate requests_futures, although its not as good
- Might be nicer to store the log msg as an object rather than a dict (such as MozDefLog.timestamp, MozDefLog.tags, etc.)
- Might want to limit event category to well-known default categories instead of a string (such as "authentication", "daemon", etc.)
- Might want to limit event severities to well-known default severities instead of a string (such as INFO, DEBUG, WARNING, CRITICAL, etc.)
- Might want to add documentation how to add your own CA certificate for this program to use
- Could use unittest module ;)
