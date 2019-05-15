====================================
Disspcap - pcap dissector
====================================

`Disspcap <https://github.com/danieluhricek/disspcap>`_ is a minimalist library for packet examination implemented in C++ and with available binding to Python. 
Attempting to be *simple* and *fast*. Disspcap provides simple alternative to robust
pcap-related libraries and frameworks.


Depedencies
***********

* Linux (tested on Debian)
* C++ compiler supporting C++11
* libpcap-dev package
* pybind11 >= 2.2 (Python only)


Python package
**************

.. code:: bash

    $ pip install disspcap

C++ shared library
******************

.. code:: bash

    $ git clone https://github.com/danieluhricek/disspcap
    $ cd disspcap
    $ make


Docs
****
`<https://disspcap.readthedocs.io>`_
