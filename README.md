# Native Ethernet Library For Teensy 4.1

Teensy 4.1 is automatically configured for Ethernet use.
This library uses my FNET fork and is a required download.
https://github.com/vjmuzik/FNET


Just change <Ethernet.h> to <NativeEthernet.h> to use this library and the rest is taken care of.
The API is a direct replacement for the normal Ethernet.h library aside from sketches that use direct calls to w5100.h

I've done quite a bit of testing to ensure compatibility as much as possible, but if you find any issues please report them.


http://www.pjrc.com/teensy/td_libs_Ethernet.html
