# host-witness
Identify a host's source IP by Certificate's Common Name.

USE WITH YOUR OWN RISK!

DO NOT USE IT IF YOU DON'T KNOW WHAT YOU ARE DOING!!!

SNI SSL is also supported!

Dependencies
------------
 - Python3.3+(Beacuse we need IP Address Library from Python3.3 to calculate IP Address Range)
 - Python3-openssl

Installation
------------
In Ubuntu:
```
sudo apt-get install python3-dev python3-openssl -y
```


Usage
-----

```
python3 witness.py [test host list] [output file name]
```
Example:
```
python3 witness.py text.lst output.lst
```

the test.lst example and output.lst example is included in the repository.

Notice: host-witness will not clear output.lst first if there was anything include this file!!


License
-------
MIT
