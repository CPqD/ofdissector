ofdissector
===========

Wireshark dissectors for OpenFlow 1.1+

Build/Install
=============

Depedencies
-----------
 * glib >= 2.0
 * Wireshark >= 1.4.0
 * SCons >= 2.0

The build requires wireshark include files somewhere on your system.  You can 
set the WIRESHARK environment variable to the directory that your include files 
live in (e.g. the root of an svn checkout) - this should be such that 
<epan/packet.h> is a valid include.

On Linux the build should work out of the box (once you set WIRESHARK), 
producing libpacket-openflow.so, which needs to be renamed to openflow.so and 
moved into an acceptable wireshark plugin directory 
(/usr/local/lib/wireshark/plugins/<ver>/ for example).  

The Windows build should also pretty much work out of the box, provided you have
sufficiently set up your system for building Wireshark itself.

The MacOS X build should work if you've built/installed Wireshark yourself (e.g.
via Brew), which means you'll have all the build dependencies already satisfied.
You will still need to download the source distribution that matches the version
you installed via Brew so that you can run `configure` and generate config.h for
your environment.  Once you have a config.h for your environment, the scons 
build should work as it does on any other posix system.

Install
-------
1) Set the Wireshark include directory. In Linux, this should be:
   $ export WIRESHARK=/usr/include/wireshark
2) Run:
   $ cd src
   $ scons install
3) Run Wireshark

Test
----
1) Run:
   $ cd test
   $ make
   $ ./server (will stay listening forever)
2) Go to Wireshark and start capture on lo
3) Run:
   $ ./client

Several messages should appear. You can customize them in main function in 
client.c, and then repeat the steps above to see the results.
