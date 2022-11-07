D-Link Control
==============
This project provides a small utility (`dlinkcontrol`) to control your
D-Link "DWM-222 4G LTE USB Adapter" from the command line.
It works by sending HTTP command to the DWM-222's embedded WEB Server.

> **NOTE:** This tool was developed and tested on the *FreeBSD* OS and
> the instruction provided here are meant for the *FreeBSD* OS.
> On other Operating Systems, this tool may even fail to compile.

Features
--------
**D-Link Control** provides the following features:

* read the ICCID (SIM unique identification number)
* unlock the SIM
* reset SIM's PIN (**WARNING:** This feature is UNTESTED!)
* retrieve ISP's provided DNS servers
* read, write and delete Short Messages (SMS)
* start and stop 3G/4G connection
* keep count of the transferred bytes

To keep count of the transferred bytes, the name of two files must be
provided (when the connection is started):

* an "account file", to store the amount of transferred bytes (both
  received and trasmitted)
* a "PID file", to store the Process ID of a daemon process that will
  periodically update the account file

The daemon will be killed when the connection is stopped.

Run `dlinkcontrol` without options for a detailed list of available
commands and options.

Building
--------
To build from a clone of the repository, you need the following tools:

* autoconf 2.71
* automake 1.16.5
* gnulib (install a recent version or clone it from
  <git://git.sv.gnu.org/gnulib.git>)

From the root directories of the **D-Link Control** cloned repository,
run:

```
gnulib-tool --update
autoreconf -i
```

This will build the `configure` script.

To actually build and install the executable, run:

```
./configure
make
make install
```

See also `./configure --help`.

If available, the `configure` script will try to link against `libcurl`.
If not found, it will fall-back to the native `libfetch`.

`libcurl` is the best option, as it allow to time-out the HTTP requests,
should the embedded WEB Server freeze or the whole DWM-222 crash /
reboot (which seems to happen regularly).

> **NOTE:** `libfetch` also has a time-out knob, but it does not work.

About the DWM-222 adapter
-------------------------
The "DWM-222 4G LTE USB Adapter" provide several protocols to interact
with:

* QMI (Qualcomm MSM Interface)
* RNDIS
* CDC-ECM

For the *FreeBSD* lacks a QMI driver, we can only interact with the
DWM-222 through the RNDIS or CDC-ECM protocols.
However, when the DWM-222 is plugged in the USB port, it will activate,
by default, the QMI protocol interface.

Alongside the QMI protocol interface there will be also a Mass Storage
iterface, providing two units:

1. a micro-SD unit (e.g., `/dev/da0`)
2. a CD-ROM unit (e.g., `/dev/cd0`)

To activate the RNDIS protocol interface, you have to "eject" the CD-ROM
unit:

```
camcontrol eject /dev/cd0
```

If for some reason you prefer the CDC-ECM protocol interface, in
addition to the previous command, also run:

```
usbconfig -d X.Y set_config 1
```

Where `X.Y` are the USB bus number and device address assigned to
DWM-222 (run `usbconfig` without options to list all the attached USB
devices).

Once the RNDIS (or the CDC-ECM) protocol interface is up, the `urndis`
(or `cdce`) driver will be loaded and a new network interface, e.g.,
`ue0`, will be created.
To activate tethering through this interface, you may need to add the
following to your `/etc/rc.conf`:

```
if_config_ue0="SYNCDHCP"
```

By default, the gateway address is set to 192.168.0.1.
The embedded WEB Server is reachable at the same IP address, port 80.
It provides a WEB interface to configure and manage the device.

Configuration must be done through the WEB interface, for the
`dlinkcontrol` utility provides no such feature.

Firmware Upgrade
----------------
As of now (november 2022) there are two firmware revisions available for
the DWM-222 device: A1 and A2.

Revision A1 does not work with *FreeBSD* (tested on release 13.1), that
is, it gives you no CD-ROM unit, so there is no means to activate the
RNDIS / CDC-ECM protocol interface.

You can download revision A2 from D-Link's product support web page, but
you'll need Windows to run the upgrade utility.
It is possible to run it from *VirtualBox* (as I did, from *Linux*),
you'll need to:

1. install Windows 10
2. install the *VirtualBox* Extension Pack to enable USB 2.0 support
   (*VirtualBox* 7 should not need this)
3. add an "USB Device Filter", but do not specify any vendor id /
   product id: use the USB icon on the right side of the lower status
   bar to select the DWM-222 device
4. run the upgrade utility and follow the instructions
5. keep selecting all the USB vendor id / product id the DWM-222 will
   cicle through during the upgrade process

> **WARNING:** Firmware upgrade is always a risky process, especially if
> done from a Virtual Machine.
> Don't blame me if you brick your brand new DWM-222!

License
-------
Copyright 2022 Francesco Lattanzio

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
