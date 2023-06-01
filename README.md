# parseusbs
Parses USB connection artifacts from offline Registry hives


Registry parser, to extract USB connection artifacts from SYSTEM, SOFTWARE, and NTUSER.dat hives  
Author: Kathryn Hedley, khedley@khyrenz.com  
Copyright 2023 Kathryn Hedley, Khyrenz Ltd  


Runs in Python3  
Uses regipy offline hive parser library from Martin G. Korman: https://github.com/mkorman90/regipy/tree/master/regipy  


Extracts from the following keys/values:  
  SYSTEM\Select\Current -> to get kcurrentcontrolset  
  SYSTEM\kcurrentcontrolset\Enum\USB  
  SYSTEM\kcurrentcontrolset\Enum\USBSTOR  
  SYSTEM\kcurrentcontrolset\Enum\SCSI  
  SYSTEM\MountedDevices  
  SOFTWARE\Microsoft\Windows Portable Devices\Devices  
  SOFTWARE\Microsoft\Windows Search\VolumeInfoCache  
  NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop  
  NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2  


Dependencies:  
  pip3 install regipy  


Limitations:  
  Does not clean dirty hives - please play back transaction logs before running this tool  


Usage:  
  parseUSBs.py <options>  
	Options:  
		-h 		          	Print this help message  
		-s    <SYSTEM hive>  
		-w    <SOFTWARE hive>	 	- This argument is optional. If omitted, some drive letters and volumes names may be missing in the output  
		-u    <NTUSER.dat hive> 	- This argument is optional & multiple can be provided. If omitted, connections to user accounts won\'t be made  
		-o    <csv|keyval>		Output to either CSV or key-value pair format. Default is key-value pairs  

Example:  
    python3 parseUSBs.py -s SYSTEM -w SOFTWARE -u NTUSER1.DAT -u NTUSER2.DAT  
