#!/bin/python

# Registry parser, to extract USB connection artifacts from SYSTEM, SOFTWARE, and NTUSER.dat hives
# Author: Kathryn Hedley, khedley@khyrenz.com
# Copyright 2024 Kathryn Hedley, Khyrenz Ltd

# Uses regipy offline hive parser library from Martin G. Korman: https://github.com/mkorman90/regipy/tree/master/regipy
# Uses python-evtx parser from Willi Ballenthin: https://pypi.org/project/python-evtx/
# Uses LnkParse3 parser from Matus Jasnicky: https://github.com/Matmaus/LnkParse3

# Extracts from the following Registry keys/values:
## SYSTEM\Select\Current -> to get kcurrentcontrolset
## SYSTEM\kcurrentcontrolset\Enum\USB
## SYSTEM\kcurrentcontrolset\Enum\USBSTOR
## SYSTEM\kcurrentcontrolset\Enum\SCSI
## SYSTEM\kcurrentcontrolset\Enum\SWD\WPDBUSENUM
## SYSTEM\MountedDevices
## SOFTWARE\Microsoft\Windows Portable Devices\Devices
## SOFTWARE\Microsoft\Windows Search\VolumeInfoCache
## NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop
## NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2

# Parses the following Event Logs:
## Event ID 1006 in Microsoft-Windows-Partition%4Diagnostic.evtx
## Event ID 1001 in Microsoft-Windows-Storsvc%4Diagnostic.evtx (EID 1002 parsing removed as no extra info)

# Parses all user account's LNK files, to extract drive letters for objects opened after the closest connection time to the object access/creation

# Bypasses Windows permission errors on a mounted volume using chmod
## This only works if you're running the Terminal window as Administrator

# CSV option produces two CSV output files - one showing USB info (usb-info.csv) and a timeline of connection and disconnection times (usb-timeline.csv)
## These output files are written to the same folder the script was run from
## Events within 2 seconds of each other are merged 

# Dependencies:
## pip3 install regipy python-evtx LnkParse3

# Limitations:
## Only parses Registry hives & Event Logs; does not parse any other artefacts
## Will only replay Registry transaction logs if they're in the same folder as the provided hive
## Only parses event logs and LNK files if the Volume option is used
## Does not detect or clean dirty event logs

# Importing libraries
import sys, os, stat, ctypes, platform, base64, time
import Evtx.Evtx as evtx
import LnkParse3
from xml.dom import minidom
from datetime import datetime,timedelta,timezone
from regipy.registry import RegistryHive
from regipy.recovery import apply_transaction_logs
from regipy.utils import calculate_xor32_checksum
from binascii import hexlify

#Defining object for a connection
class DeviceConnection:
	# initialising new object to empty values
	def __init__(self):
		self.time = ""
		self.connectionType = ""
		self.volumeLabel = ""
		self.volumeSerial = ""
		self.filesystem = ""
		self.partStyle = ""
		self.volumeCount = ""
		self.driveLetter = ""
		self.deviceSize = ""
		self.ejected = ""
		self.formatMethod = ""

#Defining object for a USB device
class ExternalDevice:
	# initialising new object to empty values
	def __init__(self):
		self.name = ""
		self.iSerialNumber = ""
		self.firstConnected = ""
		self.lastConnected = ""
		self.lastRemoved = ""
		self.connections = []
		self.lastDriveLetter = ""
		self.volumeName = ""
		self.diskId = ""
		self.userAccounts = []
		self.altSerials = []

	# method to set connection/disconnection time
	def addConnection(self, khyc):
		self.connections.append(khyc)
	# method to get other connection timestamps
	def getConnections(self):
		return self.connections
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
	# method to add serial number
	def addAltSerial(self, kser):
		self.altSerials.append(kser)

#Function to display tool, header
def printHeader() -> None:
	print("parseUSBs version 1.7")
	print("Registry parser, to extract USB connection artifacts from registry hives, event logs and LNK files")
	print("Author: Kathryn Hedley, khedley@khyrenz.com")
	print("Copyright 2025 Kathryn Hedley, Khyrenz Ltd")
		
# Function to display help info
def printHelp() -> None:
	print('Usage: python3 parseUSBs.py <options>')
	print('Options:')
	print('	-h 			Print this help message')
	print('	-s <SYSTEM hive>	Parse this SYSTEM hive')
	print('	-u <NTUSER.dat hive> 	Parse this NTUSER.DAT hive. This argument is optional & multiple can be provided.')
	print('				If omitted, connections to user accounts won\'t be made')
	print('	-v <drive letter>	Parse this mounted volume')
	print('				Use either this "-v" option or the individual hive options.')
	print('				Using this option means USB-related Windows Event Logs will also be parsed.')
	print('				If this option is provided, "-s|-u|-w" options will be ignored')
	print('				*IMPORTANT*: Please make sure you are running this script in a terminal window that is running')
	print('				as Administrator to auto-bypass Windows permission issues')
	print('	-w <SOFTWARE hive>	Parse this SOFTWARE HIVE. This argument is optional.')
	print('				If omitted, some drive letters and volume names may be missing in the output')
	print('	-o <csv|keyval>		Output to either CSV or key-value pair format. Default is key-value pairs')
	print('				Note: outputs two CSV files - usb-info.csv & usb-timeline.csv')
	print('	-d <output dir>		Define output folder if \'-o csv\' is used. Default is in same folder as the script')
	print()
	print('Example commands:')
	print('	python3 parseUSBs.py -s C:/Windows/System32/config/SYSTEM -w C:/Windows/System32/config/SOFTWARE')
	print('		-u C:/Users/user1/NTUSER.DAT -o csv')
	print('	python3 parseUSBs.py -s SYSTEM -w SOFTWARE -u NTUSER.DAT_user1 -u NTUSER.DAT_user2')
	print('	(In Windows CMD as Administrator:) python3 parseUSBs.py -v F:')
	print('	(On WSL as Administrator:) python3 parseUSBs.py -v /mnt/f')
	print()

# Function to convert Key Last Write timestamp to readable format
# Usage - convertWin64time(kusbstorkey.header.last_modified)
def convertWin64time(khyts: int) -> datetime:
	return (datetime(1601, 1, 1) + timedelta(microseconds=(khyts//10))).replace(tzinfo=timezone.utc).isoformat()

# Function to get timestamp value (if present) as readable timestamp
def getTime(reg: RegistryHive, regkey: str) -> str:
	try:
		khyconn = reg.get_key(regkey).get_value('(default)').isoformat()
	except:
		khyconn = ""
	return khyconn

# Function to output parsed device data as CSV
def outputCSV(dev: list[ExternalDevice], outfile: str) -> None:
	of = open(outfile, "w")
	
	of.write('Value:,DeviceFriendlyName,iSerialNumber(|otherSerialNumbers),DiskID,FirstConnected,LastConnected,LastRemoved,OtherConnections,OtherDisconnections,LastDriveLetter,VolumeName,VolumeSerials,UserAccounts\n')
	of.write('Source:,USBSTOR-FriendlyName,USBSTOR/EventLogs,SCSI,USBSTOR-0064,USBSTOR-0066,USBSTOR-0067,SOFTWARE-VolumeInfoCache/Microsoft-Windows-Partition%4Diagnostic.evtx,Microsoft-Windows-Partition%4Diagnostic.evtx,SYSTEM-MountedDevices/SOFTWARE-Windows Portable Devices,SOFTWARE-VolumeInfoCache/SOFTWARE-Windows Portable Devices,Microsoft-Windows-Partition%4Diagnostic.evtx,NTUSER-MountPoints2\n')
	
	for khyd in dev:
		uacc=""
		for khyu in khyd.userAccounts:
			if uacc == "":
				uacc = khyu
			else:
				uacc += "|"+khyu
		oconn=""
		for khyocn in khyd.connections:
			if khyocn.connectionType == "Connect":
				if oconn == "":
					oconn = khyocn.time
				else:
					oconn += "|"+khyocn.time
		dconn=""
		for khydcn in khyd.connections:
			if khydcn.connectionType == "Disconnect":
				if dconn == "":
					dconn = khydcn.time
				else:
					dconn += "|"+khydcn.time
		vsns=""
		for khyvs in khyd.connections:
			if khyvs.volumeSerial != "":
				if vsns == "":
					vsns += khyvs.volumeSerial + " (" + khyvs.partStyle + ";" + khyvs.filesystem + ")"
				else:
					vsns += " | " + khyvs.volumeSerial + " (" + khyvs.partStyle + ";" + khyvs.filesystem + ")"
		dsns=khyd.iSerialNumber
		for khyds in khyd.altSerials:
			if khyds != "":
				dsns += "|"+khyds
				
		of.write(','+str(khyd.name)+','+dsns+','+str(khyd.diskId)+','+khyd.firstConnected+','+khyd.lastConnected+','+khyd.lastRemoved+','+oconn+','+dconn+','+str(khyd.lastDriveLetter)+','+str(khyd.volumeName)+','+vsns+','+uacc+"\n") 
	of.close()

# Function to output parsed device data as Key/Value pairs
def outputKV(dev: list[ExternalDevice]) -> None:
	for khyd in dev:
		print("Device Friendly Name:", str(khyd.name))
		print("iSerialNumber:", str(khyd.iSerialNumber))
		for khysns in khyd.altSerials:
			print("Other Serial Number:", khysns)
		print("DiskID (SCSI):", str(khyd.diskId))
		print("First Connected:", khyd.firstConnected)
		print("Last Connected:", khyd.lastConnected)
		print("Last Removed:", khyd.lastRemoved)
		for khycn in khyd.connections:
			if khycn.connectionType == "Connect":
				print("Other Connection:", khycn.time)
		for khycn in khyd.connections:
			if khycn.connectionType == "Disconnect":
				print("Other Disconnection:", khycn.time)
		print("Last Drive Letter:", str(khyd.lastDriveLetter))
		print("Volume Name:", str(khyd.volumeName))
		for khycn in khyd.connections:
			if khycn.volumeSerial != "":
				print("VSN:", str(khycn.volumeSerial) + " (" + str(khycn.partStyle) + ", " + str(khycn.filesystem) + ")")
		for khyu in khyd.userAccounts:
			print("User Account:", khyu)
		print()

# Function to output timeline of connections & disconnections as CSV
def outputTimeline(kdevs: list[ExternalDevice], outf: str) -> None:
	of = open(outf, "w")
	
	#Writing out column headers
	of.write('Timestamp,Type,DeviceFriendlyName,iSerialNumber,DiskID,DriveLetter,VolumeName,VolumeSerial,PartitionStyle,Filesystem,VolumeCount,FormatMethod, DeviceSize,SafelyEjected\n')
	
	for kdv in kdevs:	
		for kdc in kdv.connections:
			if timesInRange(kdc.time, kdv.firstConnected, 1) and str(kdc.connectionType) == "Connect":
				of.write(kdv.firstConnected+",First Connect,"+str(kdv.name)+","+str(kdv.iSerialNumber)+","+str(kdv.diskId)+","+str(kdc.driveLetter)+","+str(kdc.volumeLabel)+","+str(kdc.volumeSerial)+","+str(kdc.partStyle)+","+str(kdc.filesystem)+","+str(kdc.volumeCount)+","+(kdc.formatMethod)+","+str(kdc.deviceSize)+","+str(kdc.ejected)+"\n")
			elif kdv.lastConnected != "" and timesInRange(kdc.time, kdv.lastConnected, 1) and str(kdc.connectionType) == "Connect":
				of.write(kdv.lastConnected+",Last Connect,"+str(kdv.name)+","+str(kdv.iSerialNumber)+","+str(kdv.diskId)+","+str(kdc.driveLetter)+","+str(kdc.volumeLabel)+","+str(kdc.volumeSerial)+","+str(kdc.partStyle)+","+str(kdc.filesystem)+","+str(kdc.volumeCount)+","+(kdc.formatMethod)+","+str(kdc.deviceSize)+","+str(kdc.ejected)+"\n")
			elif kdv.lastRemoved != "" and timesInRange(kdc.time, kdv.lastRemoved, 1) and str(kdc.connectionType) == "Disconnect":
				of.write(kdv.lastRemoved+",Last Disconnect,"+str(kdv.name)+","+str(kdv.iSerialNumber)+","+str(kdv.diskId)+","+str(kdc.driveLetter)+","+str(kdc.volumeLabel)+","+str(kdc.volumeSerial)+","+str(kdc.partStyle)+","+str(kdc.filesystem)+","+str(kdc.volumeCount)+","+(kdc.formatMethod)+","+str(kdc.deviceSize)+","+str(kdc.ejected)+"\n")
			else:
				of.writelines(kdc.time+","+str(kdc.connectionType)+","+str(kdv.name)+","+str(kdv.iSerialNumber)+","+str(kdv.diskId)+","+str(kdc.driveLetter)+","+str(kdc.volumeLabel)+","+str(kdc.volumeSerial)+","+str(kdc.partStyle)+","+str(kdc.filesystem)+","+str(kdc.volumeCount)+","+(kdc.formatMethod)+","+str(kdc.deviceSize)+","+str(kdc.ejected)+"\n")
	of.close()
	
# Function to check if iSerialNumber in array of ExternalDevice objects
def snInDevArray(ksn: str, kdevarr: list[ExternalDevice]) -> bool:
	for khyd in kdevarr:
		if ksn == khyd.iSerialNumber:
			return True
	return False
	
# Function to check for dirty Registry Hive
def is_dirty(khv: RegistryHive) -> bool:	
	if khv.header.primary_sequence_num != khv.header.secondary_sequence_num:
		print(khv.name.split('\\')[-1] + " is dirty! Sequence numbers don't match; applying transaction logs...")
		return True
		
	chksum = calculate_xor32_checksum(khv._stream.read(508))
	if khv.header.checksum != chksum:
		print(khv.name.split('\\')[-1] + " is dirty! Checksum doesn't match; applying transaction logs...")
		return True
	
	print(khv.name.split('\\')[-1] + " is clean")
	return False

# Function to replay transaction logs
# Uses regipy apply_transaction_logs(hive_path, primary_log_path, secondary_log_path=None, restored_hive_path=None, verbose=False)
def replay_logs(khvpath: str) -> RegistryHive:
	#Looking for log files in same path as hive
	print("Looking for LOG files: "+khvpath+".LOG1 & "+khvpath+".LOG2 in same location as "+khvpath)
	log1=log2=""
	logsexist=False
	if os.path.exists(khvpath+".LOG1"):
		log1=khvpath+".LOG1"
		logsexist=True
	if os.path.exists(khvpath+".LOG2"):
		log2=khvpath+".LOG2"
		logsexist=True
	
	if logsexist:
		updatedhive=None
		updatedhive, dirtypagecount = apply_transaction_logs(khvpath, log1, log2, updatedhive, False)
		print("Updated hive created: "+updatedhive)
		return RegistryHive(updatedhive)
	else:
		print("Log files not found - dirty hive is being processed")
		return RegistryHive(khvpath)

# Function to change permissions on a folder to allow Registry hives to be accessed
def pychmod(kpath: str) -> None:
	try:
		if (not inLinux(kpath)) and os.path.exists(kpath):
			os.chmod(kpath, 0o777)
			print("Permissions modified successfully on path: "+kpath)
		else:
			print("Path not found:", kpath)
	except PermissionError:
		print("Error: Permissions could not be changed on the folder:", kpath)
		print("**Please check you are running your Terminal as an Administrator**")
		print()
		sys.exit()

# Function to check python is running in an admin terminal
def isAdmin(volp: str) -> bool:
	try:
		if volp.startswith("/"):
			# Cannot determine if running as admin but in Linux, so default to True
			return True
		elif 'wsl' in platform.platform().lower():
			# Cannot determine if running as admin but in WSL, so default to True
			return True
		elif platform.platform().lower().startswith('linux'):
			return os.getuid() == 0
		elif platform.platform().lower().startswith('windows'):
			return ctypes.windll.shell32.IsUserAnAdmin() != 0
	# Default to False
	finally:
		return False

# Function to check python is running in Linux-based terminal
def inLinux(volp: str) -> bool:
	try:
		if 'wsl' in platform.platform().lower():
			return False
		elif 'linux' in platform.platform().lower():
			return True
		elif volp.startswith("/"):
			return True
		elif platform.platform().lower().startswith('linux'):
			return True
		elif platform.platform().lower().startswith('windows'):
			return False
		elif ":" in volp:
			return False
	except Exception:
		#empty value
		pass		
	
	# Default to False
	return False
		
# Function to get filesystem type from hex VBR
def getFSFromVbr(khexvbr: str) -> str:
	#Get FAT32 filesystem standard filesystem type label
	fstype=hexToText(khexvbr[164:180])
	if fstype.startswith("FAT"):
		return fstype.strip()
		
	#Otherwise, use OEM label if possible
	fstype=hexToText(khexvbr[6:22]).upper()
	if fstype.startswith("EXFAT"):
		return "exFAT"
	elif fstype.startswith("NTFS"):
		return "NTFS"
	return ""

# Function to get VSN from VBR depending on filesystem type offset
def getVsnFromVbr(khexvbr: str) -> str:
	kfstype=getFSFromVbr(khexvbr)
	vbrvsnoffset=0
	vbrvsnsize=4
	#Getting VSN offset & size (where not 4)
	if kfstype.startswith("exFAT"):
		vbrvsnoffset=100
	elif kfstype.startswith("NTFS"):
		vbrvsnoffset=72
		vbrvsnsize=8
	elif kfstype.startswith("FAT"):
		vbrvsnoffset=67
	
	if vbrvsnoffset > 0:
		khyvsn=khexvbr[(vbrvsnoffset*2):((vbrvsnoffset+vbrvsnsize)*2)]
		return(flipEndianness(khyvsn)) #+" (" +kfstype+")")
	else:
		return ""

# Function to use OEM name from hex VBR to try & determine how the volume was formatted, if possible
def getOEMFromVbr(kyhexvbr: str) -> str:
	khyoem=hexToText(kyhexvbr[6:22]).upper()
	if khyoem.startswith("MSDOS") or khyoem.startswith("MSWIN"):
		return "MS Windows format"
	if khyoem.startswith("NTFS"):
		return "MS Windows Disk Management"
	if khyoem.startswith("MTOOL"):
		return "Linux mtool mformat"
	if khyoem.startswith("MKDOSFS"):
		return "Linux mtool mformat"
	if khyoem.startswith("BSD"):
		return "macOS Disk Utility / BSD"
	#Unknown, gibberish, or blank field - return empty string
	return ""
	
# Function to change endianness of a hex string
def flipEndianness(khexstr: str) -> str:
	outstr=""
	try:
		for i in range(len(khexstr),0,-2):
			outstr=outstr+khexstr[i-2:i]
	finally:
		return outstr

# Function to convert hex string to ascii text
def hexToText(khyhexstr: str) -> str:
	outstr=""
	for i in range(0,len(khyhexstr),2):
		outstr=outstr+chr(int(khyhexstr[i : i + 2], 16))
	return outstr

# Function to strip out prepended data from S/N if UASP device
def stripUaspMarker(ksn: str) -> str:
	umarker="MSFT30"
	if ksn.startswith(umarker):
		return ksn[len(umarker):]
	else:
		return ksn
	
# Check if two (str) dates are within 'secdiff' seconds of each other (either way)
def timesInRange(ktm1: str, ktm2: str, secdiff: int) -> bool:
	if ktm1 == "" or ktm2 == "" or secdiff < 1:
		return False
	ktm1Secs = datetime.fromisoformat(ktm1).timestamp()
	ktm2Secs = datetime.fromisoformat(ktm2).timestamp()

	if ktm1Secs <= (ktm2Secs + secdiff) and ktm1Secs >= (ktm2Secs - secdiff):
		return True
	else:
		return False
		
# Get difference bwetween two dates, assuming ktm should be AFTER basetm
def datetimeDiff(basetm: str, ktm: str) -> float:
	ktmSecs = datetime.fromisoformat(ktm).timestamp()
	kbasetmSecs = datetime.fromisoformat(basetm).timestamp()
	return round(ktmSecs,15) - round(kbasetmSecs,15)

# Remove all characters after the last '&' character in a string, including the '&' itself
def removeAmpEnd(kystr1: str) -> str:
	amp = kystr1.find('&', 2)
	remove = len(kystr1)-amp
	
	if amp > 0:
		return kystr1[:-remove]
	else:
		return kystr1


### ---MAIN function--- ###
if __name__ == "__main__":
	printHeader()

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
	outcsvdir=""
	
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
		if next == 'outputdir':
			outcsvdir=karg
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
		if karg == "-d":
			next='outputdir'
			
	#Output files if CSV option is selected - outputs to two files: usb-info & timeline
	if outcsvdir != "":
		csvoutfile = outcsvdir+"/usb-info.csv"
		timelinefile = outcsvdir+"/usb-timeline.csv"
	else:
		csvoutfile = "usb-info.csv"
		timelinefile = "usb-timeline.csv"

	#if volume option is provided, find Registry hives
	if kmtvol:
		if not kmtvol.endswith("/"):
			kmtvol = kmtvol + "/"

		#Checking if volume is full mounted image or a KAPE triage image & getting drive letter it's mounted as...
		dl=""
		items=os.popen('ls -l '+kmtvol+' | awk \'{print $9}\'').read()
		for i in items.split('\n'):
			if len(i) == 1:
				dl=i
		if dl!="" and os.path.isdir(kmtvol+dl+"/Windows"):
			kmtvol+=dl+"/"	
		sysconfdir=kmtvol+"Windows/System32/config"
		
		#Changing Windows permissions to allow access to each system hive
		pychmod(sysconfdir)
		
		sysHive=sysconfdir+"/SYSTEM"
		swHive=sysconfdir+"/SOFTWARE"
		userHives=[]
		
		if os.path.exists(kmtvol+"Users"):
			userfolders = [f.path for f in os.scandir(kmtvol+"Users") if f.is_dir()]
			for usrdir in userfolders:
				#Changing Windows permissions to allow access to each NTUSER hive
				pychmod(usrdir)
				#Store paths to NTUSER hives
				userHives.append(usrdir+"/NTUSER.DAT")

	#Event logs to parse to get USB connections
	partDiagEvtx=kmtvol+"Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx"
	partDiagEvtId='1006'
	storsvcEvtx=kmtvol+"Windows/System32/winevt/Logs/Microsoft-Windows-Storsvc%4Diagnostic.evtx"
	storsvcEvtId='1001'

	# Checking hives exist & opening to extract keys & values
	if os.path.isfile(sysHive):
		SYSTEM = RegistryHive(sysHive)
		#Checking if hive is dirty
		if is_dirty(SYSTEM):
			SYSTEM = replay_logs(sysHive)
	else:
		print("SYSTEM Hive '"+sysHive+" ' does not exist")
		print()
		printHelp()
		sys.exit()
	if os.path.isfile(swHive):
		SOFTWARE = RegistryHive(swHive)
		swflag=True
		#Checking if hive is dirty
		if is_dirty(SOFTWARE):
			SOFTWARE = replay_logs(swHive)
	else:
		print("SOFTWARE Hive not being parsed")
	NTUSER=[]
	if not userHives:
		print("User hives not being parsed")
	for kuh in userHives:
		if os.path.isfile(kuh) and not "Default" in kuh:
			nthv=RegistryHive(kuh)
			#Checking if hive is dirty
			if is_dirty(nthv):
				nthv = replay_logs(kuh)
			#Appending hive to list
			NTUSER.append(nthv)
			ntuflag=True
			#Checking if hive is dirty

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
			
			#Get device serial number, removing all after the last '&' character, including the '&' itself
			newDev.iSerialNumber = removeAmpEnd(kusbstorsnkey.name)
			
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

	# Iterating over SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM to determine volume name or last drive letter...
	for kkwpdkey in SYSTEM.get_key("SYSTEM\\" + khycurrentcontrolset + "\\Enum\\SWD\\WPDBUSENUM").iter_subkeys():
		#Checking if key name contains iSerialNumber (>1 hash symbol) or DiskID (1 hash symbol)
		ksnum = ""
		kdid = ""
		if kkwpdkey.name.count('#') > 1:
			ksnum = removeAmpEnd(kkwpdkey.name.split('#')[2])
		else:
			kdid = kkwpdkey.name.split('#')[0]
		
		for kdev in devices:
			if ksnum != "" and kdev.iSerialNumber.lower() in ksnum.lower(): 
				#Match to USB device in array - get data in FriendlyName value
				volName = kkwpdkey.get_value('FriendlyName')
				if ":\\" in volName:
					#Drive letter, not volume name - add to devices info if not already added
					if kdev.lastDriveLetter == "":
						kdev.setLastDriveLetter(volName)
				else: #Volume name
					if kdev.volumeName == "":
						kdev.setVolumeName(volName)
			elif kdid != "" and kdev.getDiskId().lower() and kdev.getDiskId().lower() in kdid.lower():
				#Match to USB device on Disk ID (SCSI)
				volName = kkwpdkey.get_value('FriendlyName')
				if ":\\" in volName:
					#Drive letter, not volume name - add to devices info if not already added
					if kdev.lastDriveLetter == "":
						kdev.setLastDriveLetter(volName)
				else: #Volume name
					if kdev.volumeName == "":
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
				for c in d.getConnections():
					if c.time == klwtime:
						exists = True
				if not exists:
					dc = DeviceConnection()
					dc.time = klwtime
					dc.connectionType = "Connect"
					dc.volumeLabel = kvname
					if kdletter != "":
						dc.driveLetter = kdletter
					d.addConnection(dc)
					break

	#if volume option is provided, find & parse event logs for connection & disconnection events
	if kmtvol:
		print("Opening: ", partDiagEvtx)
		with evtx.Evtx(partDiagEvtx) as evtxlog:
			for evtxrecord in evtxlog.records():
				#print(evtxrecord.xml())
				root = minidom.parseString(evtxrecord.xml())
				eId=""
				eTime=""
				parent=""
				sn=""
				make=""
				model=""
				vsn=""
				vfs=""
				vfm=""
				partStyle=""
				safeEject=""
				connect=False
				disconnect=False
				exists=False

				#Getting Event ID & time	
				sysinfo = root.getElementsByTagName('System')[0]
				eId = sysinfo.getElementsByTagName('EventID')[0].firstChild.nodeValue
				
				if eId == partDiagEvtId:
					eTime = sysinfo.getElementsByTagName('TimeCreated')[0].attributes['SystemTime'].value
					
					elements = root.getElementsByTagName('Data')
					for element in elements:
						if element.attributes['Name'].value == "ParentId":
							try:
								parent = element.firstChild.nodeValue
								#get Serial number in ParentId - everything after last '\'
								parent_sn = stripUaspMarker(element.firstChild.nodeValue[element.firstChild.nodeValue.rindex('\\')+1:])
							except:
								pass
						if element.attributes['Name'].value == "SerialNumber":
							try:
								sn = stripUaspMarker(element.firstChild.nodeValue)
							except:
								pass
						if element.attributes['Name'].value == "Manufacturer":
							try:
								make = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "Model":
							try:
								model = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "PartitionStyle":
							try:
								partStyle = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "UserRemovalPolicy":
							try:
								safeEject = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "Vbr0":
							try:
								hexvbr = base64.b64decode(element.firstChild.nodeValue).hex()
								vfs=getFSFromVbr(hexvbr)
								vsn=getVsnFromVbr(hexvbr)
								vfm=getOEMFromVbr(hexvbr)
								#Only USB connection EID 1006 events log the VBR, not disconnection events
								connect=True
							except:
								#No VBR in event entry, so this is a disconnection event
								disconnect=True
								pass
					if parent.startswith("USB\\"):
						#Setting partition style to either MBR or GPT
						if int(partStyle) == 0:
							partStyle = "MBR"
						elif int(partStyle) == 1:
							partStyle = "GPT"
						else:
							partStyle = ""
							
						#Matching this event info with Registry info for this device
						for d in devices:
							if (sn == d.iSerialNumber) or (parent_sn == d.iSerialNumber):
								#Adding info to device record - if not already present
								exists=False
								isoETime=datetime.strptime(eTime,'%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).isoformat()
								
								#Checking for other info gaps from the Registry
								if str(d.name) == "None" or str(d.name) == "":
									d.name = make + " " + model
								
								if connect:
									for c in d.getConnections():
										#Checking if event within 2 secs has already been found & recorded
										if (timesInRange(isoETime, c.time, 2)) and c.connectionType == "Connect":
											exists=True
											if dc.volumeSerial == "":
												dc.volumeSerial = vsn
											if dc.filesystem == "":
												dc.filesystem = vfs
											if dc.formatMethod == "":
												dc.formatMethod = vfm
											if dc.partStyle == "":
												dc.partStyle = partStyle
											break

									if not exists:
										dc = DeviceConnection()
										dc.time = isoETime
										dc.connectionType = "Connect"
										dc.volumeSerial = vsn
										dc.filesystem = vfs
										dc.formatMethod = vfm
										dc.partStyle = partStyle
										d.addConnection(dc)
								if disconnect:
									for c in d.getConnections():
										#Checking if event within 2 secs has already been found & recorded
										if (timesInRange(isoETime, c.time, 2)) and c.connectionType == "Disconnect":
											exists=True
											if dc.ejected == "":
												dc.ejected = safeEject
											break
									if not exists:
										dc = DeviceConnection()
										dc.time = isoETime
										dc.connectionType = "Disconnect"
										dc.ejected = safeEject
										d.addConnection(dc)
									
								#Adding extra s/n if the two don't match (and if not already noted)
								if sn != parent_sn:
									if parent_sn == d.iSerialNumber and not sn in d.altSerials:
										d.addAltSerial(sn)
									elif sn == d.iSerialNumber and not parent_sn in d.altSerials:
										d.addAltSerial(parent_sn)
		
		#StorSvc events only found to be recorded on USB connection, not disconnection
		print("Opening: ", storsvcEvtx)
		with evtx.Evtx(storsvcEvtx) as storevtxlog:
			for evtxrecord in storevtxlog.records():
				#print(evtxrecord.xml())
				root = minidom.parseString(evtxrecord.xml())
				eId=""
				eTime=""
				parent=""
				sn=""
				make=""
				model=""
				fs=""
				partStyle=""
				volCount=""
				devSize=""
				exists=False

				#Getting Event ID & time	
				sysinfo = root.getElementsByTagName('System')[0]
				eId = sysinfo.getElementsByTagName('EventID')[0].firstChild.nodeValue
				
				if eId == storsvcEvtId:
					eTime = sysinfo.getElementsByTagName('TimeCreated')[0].attributes['SystemTime'].value
					
					elements = root.getElementsByTagName('Data')
					for element in elements:
						if element.attributes['Name'].value == "ParentId":
							try:
								parent = element.firstChild.nodeValue
								#get Serial number in ParentId - everything after last '\'
								parent_sn = stripUaspMarker(element.firstChild.nodeValue[element.firstChild.nodeValue.rindex('\\')+1:])
							except:
								pass
						if element.attributes['Name'].value == "SerialNumber":
							try:
								sn = stripUaspMarker(element.firstChild.nodeValue)
							except:
								pass
						if element.attributes['Name'].value == "VendorId":
							try:
								make = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "ProductId":
							try:
								model = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "FileSystem":
							try:
								fs = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "PartitionStyle":
							try:
								partStyle = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "VolumeCount":
							try:
								volCount = element.firstChild.nodeValue
							except:
								pass
						if element.attributes['Name'].value == "Size":
							try:
								devSize = element.firstChild.nodeValue
							except:
								pass
					if parent.startswith("USB\\"):
						#Setting partition style to either MBR or GPT, if filesystem field is not blank
						if int(partStyle) == 0:
							partStyle = "MBR"
						elif int(partStyle) == 1:
							partStyle = "GPT"
						else:
							partStyle = ""
						
						#Matching this event info with other connection info for this device
						for d in devices:
							if (sn == d.iSerialNumber) or (parent_sn == d.iSerialNumber):
								#Adding info to device record - if not already present
								exists=False
								isoETime=datetime.strptime(eTime,'%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc).isoformat()
								
								for c in d.getConnections():
									#Checking if event within 2 secs has already been found & recorded							
									if timesInRange(isoETime, c.time, 2) and c.connectionType == "Connect":
										exists=True
										if str(d.name) == "None" or str(d.name) == "":
											d.name = make+" "+model
										#Checking if some fields are empty & can be populated
										if c.filesystem == "":
											c.filesystem = fs
										if c.partStyle == "":
											c.partStyle = partStyle
										if c.volumeCount == "":
											c.volumeCount = volCount
										if c.deviceSize == "":
											c.deviceSize = devSize
										if c.connectionType == "":
											c.connectionType = "Connect"
								
								if not exists:
									if str(d.name) == "None" or str(d.name) == "":
										d.name = make+" "+model
									dc = DeviceConnection()
									dc.time = isoETime
									dc.connectionType = "Connect"
									dc.filesystem = fs
									dc.partStyle = partStyle
									dc.volumeCount = volCount
									dc.deviceSize = devSize
									d.addConnection(dc)
									
								#Checking for other info gaps from the Registry
								if d.name == "":
									d.name = make + " " + model

	#Parsing LNK files to get other drive letters
	for usrdir in userfolders:
		lnkdir=usrdir+"/AppData/Roaming/Microsoft/Windows/Recent/"
		if os.path.isdir(lnkdir) and len(lnkdir) != 0:
			for f in os.listdir(lnkdir):
				if f.endswith(".lnk"):
					fpath=lnkdir+f
					try:
						data=os.popen('lnkparse -j \"'+fpath+'\"').read()
						
						if "DRIVE_REMOVABLE" in data:
							fmtime = datetime.fromtimestamp(int(os.path.getctime(fpath))).replace(tzinfo=timezone.utc).isoformat()
							
							for l in data.split('\n'):
								if "drive_serial_number" in l:
									vals = l.split(':')
									if len(vals) > 1:
										lsn = vals[1].replace("\"", "").replace(" ", "").replace(",", "")[2:]
										#Adding leading zero if missing
										if len(lsn) == 7 or len(lsn) == 15:
											lsn = "0" + lsn
								if "local_base_path" in l:
									vals = l.split(':')
									if len(vals) > 1:
										ldl = vals[1].replace("\"", "").replace(" ", "").replace(",", "")
							
							#Matching this event info with other connection info for the same device (match on VSN)
							for d in devices:
								closestconntime = ""
								closestconnsecs = datetime.fromisoformat(d.firstConnected).timestamp()
								
								for c in d.getConnections():
									#Match on device volume serial number
									if c.volumeSerial == lsn:
										#Find connection event closest to last modified time of LNK file (when path was last updated) but after connection time (>0)
										diffsecs = datetimeDiff(c.time, fmtime)
										if diffsecs > 0 and diffsecs < closestconnsecs:
											closestconntime = c.time
											
								#Adding info to connection if not already populated
								for c in d.getConnections():
									if c.time == closestconntime and c.volumeSerial == lsn:
										if c.driveLetter == "" and ldl != "":
											c.driveLetter = ldl+":\\"   
					except Exception:
						#empty value
						pass

	#Print output in CSV or key-value pair format
	print()
	if csvout:
		outputCSV(devices, csvoutfile)
		outputTimeline(devices, timelinefile)
	if kvout:
		outputKV(devices)
