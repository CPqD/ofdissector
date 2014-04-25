# Deprecation warning
This dissector is deprecated and no longer supported. We recommend the use of the newer Wireshark versions, which support several OpenFlow versions natively and should be considered the standard. These dissectors are only available in Wireshark's Git repository for now (as of version 1.10.7), so make sure you [build from the source](http://www.wireshark.org/develop.html) or [grab a development binary](http://www.wireshark.org/download/automated/).

This code will be kept here for reference purposes, but it will no longer be developed or supported.

ofdissector
===========

Wireshark dissectors for OpenFlow 1.1 and 1.2. It's based on [ng-of-dissector] by Nick Bastin.

Build/Install
=============

Dependencies
------------
 * glib >= 2.0
 * wireshark >= 1.4.0 (including development headers)
 * scons >= 2.0

The build requires wireshark include files somewhere on your system.  You can set the `WIRESHARK` environment variable to the directory that your include files live in (e.g. the root of an svn checkout) - this should be such that `<epan/packet.h>` is a valid include.

On Linux the build should work out of the box (once you set `WIRESHARK`), producing `libpacket-openflow.so`, which needs to be renamed to `openflow.so` and moved into an acceptable wireshark plugin directory (`/usr/local/lib/wireshark/plugins/<ver>/` for example). In Ubuntu, installing `wireshark-dev` and `scons` should satisfy all dependencies and provide a building environment.

The Windows build should also pretty much work out of the box, provided you have sufficiently set up your system for building Wireshark itself.

The MacOS X build should work if you've built/installed Wireshark yourself (e.g. via Brew), which means you'll have all the build dependencies already satisfied. You will still need to download the source distribution that matches the version you installed via Brew so that you can run `configure` and generate `config.h` for your environment. Once you have a `config.h` for your environment, the scons build should work as it does on any other POSIX system.

Install
-------
1. Set the Wireshark include directory. In Linux, this should be:

    ```
    sudo -s
    export WIRESHARK=/usr/include/wireshark
    ```

2. Run:

    ```
    cd ofdissector/src
    scons install
    ```

3. Run Wireshark and filter the messages. Some filter examples:
    * `of13.ofp_header`: all OpenFlow 1.3 messages
    * `of12.ofp_header.type == 10`: OpenFlow 1.2 packet-in messages

## Testing
1. Run:

    ```
    $ cd test
    $ make
    $ ./server (will listen on port 6633)
    ```

2. Go to Wireshark and start capture on `lo`

3. Run:

    ```
    $ ./client13
    ```

Several messages should appear. You can customize them in main function in client.c, and then repeat the steps above to see the results.

If you wish to generate OpenFlow 1.2 messages, run `client12`.

# TODO
**Project wide**
* Refactor FieldManager
* Add support for the old OF 1.0 dissector in parallel
* Make tests generate dump files

**1.3**
* Fully implement multipart messages
* Implement ofp_queue_get_config_request/reply dissections
* Implement ofp_flow_removed dissection
* Finishing standardizing names and keys
* Change FieldManager API and get rid of most macros.
* Prettier OXM values and masks
* Due to code generation, we can't show a default value for flag fields
  (i.e.: OFPC_FRAG_NORMAL and OFPTC_TABLE_MISS_CONTROLLER). Fix this.
* Some enums (e.g.: ofp_controller_max_len) have few values at the end of their
  ranges. This causes a segfault when some values are used and invalid strings
  with some others. Investigate this and try to solve it.

**1.2**
* Implement ofp_*_stats dissection (stats body)
* Implement ofp_queue_get_config_request/reply dissections
* Implement ofp_flow_removed dissection
* Finishing standardizing names and keys
* Change FieldManager API and get rid of most macros.
* Prettier OXM values and masks
* Due to code generation, we can't show a default value for flag fields
  (i.e.: OFPC_FRAG_NORMAL and OFPTC_TABLE_MISS_CONTROLLER). Fix this.
* Some enums (e.g.: ofp_controller_max_len) have few values at the end of their
  ranges. This causes a segfault when some values are used and invalid strings
  with some others. Investigate this and try to solve it.

**1.1**
* Adapt to new model
* Add tests

[ng-of-dissector]: https://bitbucket.org/barnstorm/ng-of-dissector
