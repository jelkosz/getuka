getuka
======

[Gerrit](https://code.google.com/p/gerrit/) to [Kanbanik](https://code.google.com/p/kanbanik/) synchornizition tool.

To install, copy the getuka.json to /etc/getuka/getuka.json and fill all the blanks (like gerrit url, login, all the mappings etc).

If you start getuka.py, it will poll gerrit, than kanbanik, synchronizes all the data, pushes the new states to kanbanik and ends. Getuka does not do any updates to gerrit.

In order to have this scrypt running periodically you can register it to cron.

Getuka requires Kanbanik version 0.2.8 or higher (or the 0.2.8-RC2).
