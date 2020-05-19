# Rootkit
An malicious program which may break your system!! Careful when use it. Be sure to keep a snapshot of your VM before run the rootkit!

This program is testing under VM with ubuntu 16.

To run it, execute:
1. make
2. make sneaky_process

Then open two terminals, the first one runs "sudo ./sneaky_process" to insert the rootkit, the second one runs all the testing commands mentioned in pdf.

There is also a shortcut for inserting rootkit without running sneaky_mod, execute "sudo insmod sneaky_mod.ko pid="the pid you want to hid"". To remove it, just "sudo rmmod sneaky_mod"
