# Info

This hook can be used to get ZIP password from "jp.co.cybird.android.conanescape01" v1.0 Android game


Steps to reproduce:
- Prepare Windows 10 32-bit Virtual Machine
- Install frida client v15.2.2 32-bit on a virtual machine
- Install frida server v15.2.2 32-bit on Anddroid phone
- Connect Android phone to virtual machine via USB (VirtualBox > Devices > USB > Samsung Android)
- Run frida server
   - adb shell "su -c /data/local/tmp/frida-server-15.2.2-android-arm --listen=127.0.0.1:5000"
- Adb forward ports
   - adb forward tcp:5000 tcp:5000
 - Run script
   - python frida_android_conanescape01_hook.py jp.co.cybird.android.conanescape01 -H 127.0.0.1:5000
- Write down hooked password
   


Notes:
  - in version 1.0 of the game developers forgot to obfuscate game's code xD  They have fixed it in v1.2...
  - zip files were handled by "net.lingala.zip4j.core" package
  - "setPassword" method from "net.lingala.zip4j.model.FileHeader" was finally hooked to get a password
