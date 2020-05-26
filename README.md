# Tesla pre-AP EPAS steering firmware patch
Normally on pre-AP Tesla vehicles the gateway constantly sends a message indicating that steering over CAN should be disabled.

This tool patches the firmware to enable steering over CAN.

## usage notes
* flashing firmware can fail and brick your EPAS, while unlikely,  
  **do not flash something that you are not willing to pay to replace**
* [comma.ai panda](https://comma.ai/shop/products/panda-obd-ii-dongle) is used to communicate with EPAS over CAN
* use a direct CAN bus communication line with the EPAS (do not flash through gateway)

## setup
```sh
pip install -r requirements.txt
```

## patching the firmware
connect [comma.ai panda](https://comma.ai/shop/products/panda-obd-ii-dongle) to EPAS and run:

```sh
./tesla-epas-patcher.py
```

## how it works
The gateway in pre-AP vehicles constantly sends an EPAS CONTROL message (CAN address 0x101) with two signals we care about:

* LDW ENABLE (1 bit)
  * 0 = DISABLE
  * 1 = ENABLE
* CONTROL TYPE (3 bits)
  * 0 = INHIBIT
  * 1 = ANGLE
  * 2 = TORQUE
  * 3 = BOTH

The gateway in pre-AP vehicles sets these signals to have a value of 0 (disabled).

The firmware patch applied by this tool changes the EPAS CONTROL (CAN address 0x101) message parsing in the EPAS to extract the least significant bit of the POWER MODE signal in the same message instead (which is 1 while driving) for the above signals.  This enables angle based steering control by setting LDW ENABLE and CONTROL TYPE to have a value of 1 while driving.
