#!/bin/python

# Registry parser, to extract USB connection artifacts from SYSTEM, SOFTWARE, and NTUSER.dat hives
# Author: Kathryn Hedley, khedley@khyrenz.com
# Copyright 2023 Kathryn Hedley, Khyrenz Ltd

# Uses regipy offline hive parser library from Martin G. Korman: https://github.com/mkorman90/regipy/tree/master/regipy

# Extracts from the following keys/values:
## SYSTEM\Select\Current -> to get kcurrentcontrolset
## SYSTEM\kcurrentcontrolset\Enum\USB
## SYSTEM\kcurrentcontrolset\Enum\USBSTOR
## SYSTEM\kcurrentcontrolset\Enum\SCSI
## SYSTEM\MountedDevices
## SOFTWARE\Microsoft\Windows Portable Devices\Devices
## SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
## NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop
## NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

# Dependencies:
## pip3 install regipy

# Limitations:
## Does not clean dirty hives - please play back transaction logs before running this tool

# Importing libraries
import sys, os
from datetime import datetime,timedelta
from regipy.registry import RegistryHive
from binascii import hexlify

#Defining object for a USB device
class ExternalDevice:
	# initialising new object to empty values
	def __init__(self):
		self.name = ""
		self.iSerialNumber = ""
		self.firstConnected = ""
		self.lastConnected = ""
		self.lastRemoved = ""
		self.otherConnection = []
		self.lastDriveLetter = ""
		self.volumeName = ""
		self.diskId = ""
		self.userAccounts = []

	# method to set other connection time
	def addOtherConnection(self, khyoc):
		self.otherConnection.append(khyoc)
	# method to get other connection timestamps
	def getOtherConnections(self):
		return self.otherConnection
	# method to set last drive letter
	def setLastDriveLetter(self, khydl):
		self.lastDriveLetter = khydl
	# method to set volume name
	def setVolumeName(self, khyvn):
		self.volumeName = khyvn
	# method to set disk ID
	def setDiskId(self, khydi):
		self.diskId = khydi
	# method to get disk ID
	def getDiskId(self):
		return self.diskId
	# method to add user account
	def addUser(self, khyu):
		self.userAccounts.append(khyu)
	# method to get user accounts
	def getUsers(self):
		return self.userAccounts

		
# Function to display help info
def printHelp():
	print('Usage: python3 parseUSBs.py <options>')
	print('Options:')
	print('	-h 			Print this help message')
	print('	-s <SYSTEM hive>	Parse this SYSTEM hive')
	print('	-u <NTUSER.dat hive> 	Parse this NTUSER.DAT hive. This argument is optional & multiple can be provided.')
	print('				If omitted, connections to user accounts won\'t be made')
	print('	-v <drive letter>	Parse this mounted volume')
	print('				Use either this "-v" option or the individual hive options.')
	print('				If this option is provided, "-s|-u|-w" options will be ignored')
	print('	-w <SOFTWARE hive>	Parse this SOFTWARE HIVE. This argument is optional.')
	print('				If omitted, some drive letters and volume names may be missing in the output')
	print('	-o <csv|keyval>		Output to either CSV or key-value pair format. Default is key-value pairs')
	print()
	print('Example commands:')
	print('python3 parseUSBs.py -s C:/Windows/System32/config/SYSTEM -w C:/Windows/System32/config/SOFTWARE -u C:/Users/user1/NTUSER.DAT -o csv')
	print('python3 parseUSBs.py -s SYSTEM -w SOFTWARE -u NTUSER.DAT_user1 -u NTUSER.DAT_user2')
	print('(In Windows CMD:) python3 parseUSBs.py -v F:')
	print('(On WSL:) python3 parseUSBs.py -v /mnt/f')
	print()
	print('Copyright 2023 Kathryn Hedley, Khyrenz Ltd')
	print()

# Function to convert Key Last Write timestamp to readable format
# Usage - convertWin64time(kusbstorkey.header.last_modified)
def convertWin64time(khyts):
	return (datetime(1601, 1, 1) + timedelta(microseconds=(khyts//10))).isoformat()

# Function to get timestamp value (if present) as readable timestamp
def getTime(reg, regkey):
	try:
		khyconn = reg.get_key(regkey).get_value('(default)').isoformat()
	except:
		khyconn = ""
	return khyconn

# Function to output parsed data as CSV
def outputCSV(dev):
	print('Value:,Device Friendly Name,iSerialNumber,FirstConnected,LastConnected,LastRemoved,OtherConnections,LastDriveLetter,VolumeName,UserAccounts')
	print('Key:,USBSTOR-FriendlyName,USBSTOR,USBSTOR-0064,USBSTOR-0066,USBSTOR-0067,SOFTWARE-VolumeInfoCache,MountedDevices/Windows Portable Devices,Windows Portable Devices,NTUSER-MountPoints2')
	
	for khyd in dev:
		uacc=""
		for khyu in khyd.userAccounts:
			if uacc == "":
				uacc = khyu
			else:
				uacc += "|"+khyu
				uacc=""
		oconn=""
		for khyocn in khyd.otherConnection:
			if oconn == "":
				oconn = khyocn
			else:
				oconn += "|"+khyocn
		print(','+khyd.name+','+khyd.iSerialNumber+','+khyd.firstConnected+','+khyd.lastConnected+','+khyd.lastRemoved+','+khyocn+','+khyd.lastDriveLetter+','+khyd.volumeName+','+uacc)

# Function to output parsed data as Key/Value pairs
def outputKV(dev):
	for khyd in dev:
		print("Device Friendly Name:", khyd.name)
		print("iSerialNumber:", khyd.iSerialNumber)
		print("First Connected:", khyd.firstConnected)
		print("Last Connected:", khyd.lastConnected)
		print("Last Removed:", khyd.lastRemoved)
		for khyocn in khyd.otherConnection:
			print("Other Connection:", khyocn)
		print("Last Drive Letter:", khyd.lastDriveLetter)
		print("Volume Name:", khyd.volumeName)
		for khyu in khyd.userAccounts:
			print("User Account:", khyu)
		print()

# Function to check if iSerialNumber in array of ExternalDevice objects
def snInDevArray(ksn, kdevarr):
	for khyd in kdevarr:
		if ksn == khyd.iSerialNumber:
			return True
	return False
	


### MAIN function ###
print("Registry parser, to extract USB connection artifacts from SYSTEM, SOFTWARE, and NTUSER.dat hives")
print("Author: Kathryn Hedley, khedley@khyrenz.com")
print("Copyright 2023 Kathryn Hedley, Khyrenz Ltd")
print()
print("*INFO*: This tool does not have capability to clean dirty hives. Please play back transaction logs before execution")

# Check & parse passed-in arguments
next=""
sysHive=""
swHive=""
userHives=[]
kmtvol=""
ntuflag=False
swflag=False
csvout=False
kvout=True
for karg in sys.argv:
	if next == 'system':
		sysHive=karg
		next=""
	if next == 'software':
		swHive=karg
		next=""
	if next == 'ntuser':
		userHives.append(karg)
		next=""
	if next == 'output':
		if karg == "csv":
			csvout=True
			kvout=False
	if next == 'volume':
		kmtvol=karg
		next=""
	if karg == "-h":
		printHelp()
		sys.exit()
	if karg == "-s":
		next='system'
	if karg == "-w":
		next='software'
	if karg == "-u":
		next='ntuser'
	if karg == "-o":
		next='output'
	if karg == "-v":
		next='volume'

#if volume option is provided, find Registry hives
if kmtvol:
	if not kmtvol.endswith("/"):
		kmtvol = kmtvol + "/"
		
	sysHive=kmtvol+"Windows/System32/config/SYSTEM"
	swHive=kmtvol+"Windows/System32/config/SOFTWARE"
	userHives=[]
	
	if os.path.exists(kmtvol+"Users"):
		userfolders = [f.path for f in os.scandir(kmtvol+"Users") if f.is_dir()]
		for usrdir in userfolders:
			userHives.append(usrdir+"/NTUSER.DAT")

# Checking hives exist & opening to extract keys & values
if os.path.isfile(sysHive):
	SYSTEM = RegistryHive(sysHive)
else:
	print("SYSTEM Hive '"+sysHive+" ' does not exist")
	print()
	printHelp()
	sys.exit()
if os.path.isfile(swHive):
	SOFTWARE = RegistryHive(swHive)
	swflag=True
else:
	print("SOFTWARE Hive not being parsed")
NTUSER=[]
if not userHives:
	print("User hives not being parsed")
for kuh in userHives:
	if os.path.isfile(kuh):
		NTUSER.append(RegistryHive(kuh))
		ntuflag=True

#initialising empty array to store device values & removing empty value that's added
devices = []

# Getting currentcontrolset value
currentVal = SYSTEM.get_key('SYSTEM\\Select').get_value('Current')
khycurrentcontrolset = 'ControlSet00' + str(currentVal)
print("currentcontrolset identified as " + khycurrentcontrolset)

# Iterating over SYSTEM\currentcontrolset\Enum\USBSTOR key...
for kusbstorkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USBSTOR").iter_subkeys():
	for kusbstorsnkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USBSTOR\\" + kusbstorkey.name).iter_subkeys():	
		newDev=ExternalDevice()
		#Get device friendly name
		newDev.name = kusbstorsnkey.get_value('FriendlyName')
		
		#Get device serial number
		if kusbstorsnkey.name.endswith('&0'):
			newDev.iSerialNumber = kusbstorsnkey.name[:-2]
		else:
			newDev.iSerialNumber = kusbstorsnkey.name
		
		#Get device timestamps (if present)
		newDev.firstConnected = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USBSTOR\\" + kusbstorkey.name + "\\" + kusbstorsnkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")
		newDev.lastConnected = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USBSTOR\\" + kusbstorkey.name + "\\" + kusbstorsnkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")
		newDev.lastRemoved = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USBSTOR\\" + kusbstorkey.name + "\\" + kusbstorsnkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")
		
		#Adding device to array if serial number not blank
		if newDev.iSerialNumber:
			devices.append(newDev)
		
# Iterating over SYSTEM\currentcontrolset\Enum\USB key looking for SCSI devices...
for kusbkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USB").iter_subkeys():
	for kusbsubkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\USB\\" + kusbkey.name).iter_subkeys():
		if kusbsubkey.name.startswith('MSFT30'):
			#SCSI device!
			khyzDev=ExternalDevice()
			#Set iSerialNumber
			khyzDev.iSerialNumber = kusbsubkey.name[6:]
			
			#Get ParentIdPrefix to map to SCSI key
			kdevParentId = kusbsubkey.get_value('ParentIdPrefix')
			
			# Iterating over SYSTEM\currentcontrolset\Enum\SCSI key...
			for kscsikey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI").iter_subkeys():
				for kscsisubkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI\\" + kscsikey.name).iter_subkeys():
					#Only adding if has Parent ID - e.g. vmware devices can be added here without a Parent ID - can't link to SCSI key
					if kdevParentId is not None and kscsisubkey.name.startswith(kdevParentId):
						#Get device friendly name
						khyzDev.name = kscsisubkey.get_value('FriendlyName')
						
						#Get Disk ID to map to Volume name
						khyzDev.setDiskId(SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI\\" + kscsikey.name + "\\" + kscsisubkey.name + "\\Device Parameters\\Partmgr").get_value('DiskId'))
						print(khyzDev.getDiskId())
						#Get device timestamps (if present)
						khyzDev.firstConnected = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI\\" + kscsikey.name + "\\" + kscsisubkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064")
						khyzDev.lastConnected = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI\\" + kscsikey.name + "\\" + kscsisubkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066")
						khyzDev.lastRemoved = getTime(SYSTEM, "SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SCSI\\" + kscsikey.name + "\\" + kscsisubkey.name + "\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067")
						
			#Adding device to array if serial number is not blank & not already in array
			if khyzDev.iSerialNumber and not snInDevArray(khyzDev.iSerialNumber, devices):
				devices.append(khyzDev)

# Iterating over SYSTEM\MountedDevices key to determine last mounted drive letters...
for kmdval in SYSTEM.get_key("SYSTEM\MountedDevices").get_values():
	if kmdval.name.startswith('\DosDevices\\'):
		try:
			khexmd=hexlify(kmdval.value)
			for d in devices:
				khexsn=bytes(d.iSerialNumber.encode('utf-16le').hex(), 'utf8')
				if khexsn in khexmd: 
					#Last drive letter found - add to devices info
					d.setLastDriveLetter(kmdval.name[-2:]+'\\')
		except:
			#empty value
			continue
	
	#Extracting disk GUID values to search NTUSER hive, only if NTUSER.dat hive provided & valid
	if ntuflag:
		if kmdval.name.startswith('\??\Volume{'):
			try:
				khexmd=hexlify(kmdval.value)
				for d in devices:
					khexsn=bytes(d.iSerialNumber.encode('utf-16le').hex(), 'utf8')
					if khexsn in khexmd: 
						#Disk GUID found - compare against NTUSER hive
						diskGuid=kmdval.name[-38:]
						
						#Iterating NTUSER.DAT hives
						for NTU in NTUSER:
							#Getting user account name from NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop
							kusername=NTU.get_key('NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders').get_value('Desktop')
							#Output is of format C:\Users\<user>\Desktop -> extracting username
							kusername=kusername.split('\\')[2]
							
							#Checking NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 for disk GUID
							for khymp in NTU.get_key('NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2').iter_subkeys():
								if khymp.name == diskGuid:
									d.addUser(kusername)
									break
			except:
				#empty value
				continue

# Iterating over SOFTWARE\Microsoft\Windows Portable Devices\Devices to determine volume name or last drive letter...
for kwpdkey in SOFTWARE.get_key("SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices").iter_subkeys():
	for kdev in devices:
		if kdev.iSerialNumber.lower() in kwpdkey.name.lower(): 
			#Match to USB device in array
			volName = kwpdkey.get_value('FriendlyName')
			if ":\\" in volName:
				#Drive letter, not volume name - add to devices info if not already added
				if kdev.lastDriveLetter == "":
					kdev.setLastDriveLetter(volName)
			else: #Volume name
				kdev.setVolumeName(volName)
		elif kdev.getDiskId().lower() and kdev.getDiskId().lower() in kwpdkey.name.lower():
			#Match to USB device on Disk ID (SCSI)
			volName = kwpdkey.get_value('FriendlyName')
			if ":\\" in volName:
				#Drive letter, not volume name - add to devices info if not already added
				if kdev.lastDriveLetter == "":
					kdev.setLastDriveLetter(volName)
			else: #Volume name
				kdev.setVolumeName(volName)

# Iterating over SOFTWARE\Microsoft\Windows Search\VolumeInfoCache to try & match up drive letter with known volume name...
for kvickey in SOFTWARE.get_key("SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache").iter_subkeys():
	#Get Drive Letter & Volume name for device
	kdletter = kvickey.name + '\\'
	kvname = kvickey.get_value('VolumeLabel')
	#Getting another potential connection time for device
	klwtime = convertWin64time(kvickey.header.last_modified)
	
	#Attempt to link on volume name to assign drive letter & other connection time
	for kdv in devices:
		if kdv.volumeName == kvname:
			if kdv.lastDriveLetter == "":
				kdv.setLastDriveLetter(kdletter)
			
			#Only adding other connection time to list if not already present
			exists=False
			for c in d.getOtherConnections():
				if c == klwtime:
					exists=True
			if not exists:
				d.addOtherConnection(klwtime)
				break
		

#Print output in CSV or key-value pair format
print()
if csvout:
	outputCSV(devices)
if kvout:
	outputKV(devices)
