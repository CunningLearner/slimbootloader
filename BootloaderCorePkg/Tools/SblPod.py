## @ SblPod.py
#
# Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
##

import os
import argparse
import subprocess
import sys
import re
import struct
import uuid
import shutil
import hashlib
from ctypes import *

sys.dont_write_bytecode = True

# =============================================
#  Compress/decompress functions
# ============================================
class LzHeader(Structure):
	_pack_ = 1
	_fields_ = [
		('Signature',       ARRAY(c_char, 4)),
		('CompressedLen',           c_uint32),
		('UnCompressedLen',         c_uint32),
		('Reserved',                c_uint32)
	]

def AddLzHeader (DstFile, SrcFile, Signature):
	fi = open(DstFile,'rb')
	di = fi.read()
	fi.close()

	lzHdr = LzHeader()
	lzHdr.Signature       = Signature[0:4]
	lzHdr.CompressedLen   = len(di)
	lzHdr.UnCompressedLen = os.path.getsize(SrcFile)
	lzHdr.Reserved        = 0

	fo = open(DstFile,'wb')
	fo.write(lzHdr)
	fo.write(di)
	fo.close()

def compress (path, alg="Lzma"):
	root_path = os.path.splitext(path)[0]
	if alg == "Lzma":
		sig = "LZMA"
	elif alg == "Lz4":
		sig = "LZ4 "
	elif alg == "":
		sig = ""
	elif alg == "Dummy":
		sig = "LZDM"
	else:
		raise Exception ("Unsupported compression '%s' !" % alg)

	if sig == "LZDM" or sig == "":
		shutil.copy(path, root_path+'.lz')
	else:
		cmdline = ["%sCompress" % alg, "-e", "-o", root_path+'.lz', path]
		sys.stdout.flush()
		x = subprocess.call(cmdline)
		if x: sys.exit(1)

	if sig != "":
		AddLzHeader(root_path+'.lz', path, sig)
	return root_path+'.lz'

def Decompress (File):
	NewFile = os.path.splitext(File)[0] + '.org'

	# Remove the Lz Header
	fi = open(File,'rb')
	di = bytearray(fi.read())
	fi.close()

	fo = open(File,'wb')
	fo.write(di[sizeof (LzHeader):])
	fo.close()

	LzHdr = LzHeader.from_buffer (di)
	if LzHdr.Signature == "LZDM":
		return File
	elif LzHdr.Signature == "LZMA":
		alg = "Lzma "
	elif LzHdr.Signature == "LZ4 ":
		alg = "Lz4"
	else:
		raise Exception ("Unsupported compression '%s' !" % alg)

	cmdline = ["%sCompress" % alg, "-d", "-o", NewFile, File]
	sys.stdout.flush()
	x = subprocess.call(cmdline)
	if x: sys.exit(1)

	return NewFile

# =====================================================
# Generate signed image
# =====================================================
def GenPubKey (PrivKey, PubKey):
	cmdline = os.path.join(os.environ.get ('OPENSSL_PATH', ''), 'openssl')
	x = subprocess.call([cmdline, 'rsa', '-pubout', '-text', '-out', '%s' % PubKey, '-noout', '-in', '%s' % PrivKey])
	if x:
		raise Exception ('Failed to generate public key using openssl !')

	data = open(PubKey, 'r').read()
	data = data.replace('\r', '')
	data = data.replace('\n', '')
	data = data.replace('  ', '')

	# Extract the modulus
	match = re.search('modulus(.*)publicExponent:\s+(\d+)\s+', data)
	if not match:
		raise Exception('Public key not found!')
	modulus  = match.group(1).replace(':', '')
	exponent = int(match.group(2))

	# Remove the '00' from the front if the MSB is 1
	if (len(modulus) != 512):
		modulus = modulus[2:]
	mod = bytearray.fromhex(modulus)
	exp = bytearray.fromhex('{:08x}'.format(exponent))

	key = "$IPP" + mod + exp
	open(PubKey, 'wb').write(key)

	return key

def SignFile (PrivKey, PubKey, InFile, OutFile, IncData = False, IncKey = False):
	# todo: check if openssl exist
	cmdline = os.path.join(os.environ.get ('OPENSSL_PATH', ''), 'openssl')
	cmdargs = [cmdline, 'dgst' , '-sha256', '-sign', '%s' % PrivKey, '-out', '%s' % OutFile, '%s' % InFile]
	x = subprocess.call(cmdargs)
	if x:
		raise Exception ('Failed to generate signature using openssl !')

	if IncData:
		bins = bytearray(open(InFile, 'rb').read())
	else:
		bins = bytearray()
	sign = open(OutFile, 'rb').read()
	bins.extend(sign)

	if IncKey:
		key = GenPubKey (PrivKey, PubKey)
		bins.extend(key)
	open(OutFile, 'wb').write(bins)


def GenSignedFile (ImageFile, OutFile, PrivKey, AuthType):
	if PrivKey == '':
		print "No private key is provided, image signing is not required"
		return ImageFile

	if AuthType != 'RSA2048':
		raise Exception ('Unsupported signing image signing method!')

	KeyPath	= os.path.splitext(PrivKey)[0]
	PubKeyFile = KeyPath+'.pub'
	GenPubKey(PrivKey, PubKeyFile)

	fi = open(ImageFile,'rb')
	di = fi.read()
	fi.close()

	if OutFile == '':
		ImagePath  = os.path.splitext(ImageFile)[0]
		OutFile = ImagePath+'.sig'
	fo = open(OutFile,'wb')
	fo.write (di)
	fo.close()

	SignFile (PrivKey, PubKeyFile, ImageFile, OutFile, True, True)
	return OutFile

# ===============================================
# Generate region image
# ===============================================
def GenRegionFile (ImageFile, RegionSize):
	if ImageFile != '':
		fi = open(ImageFile,'rb')
		Bins = bytearray(fi.read())
		fi.close()
		ImagePath  = os.path.splitext(ImageFile)[0]
		RegionFile = ImagePath+'.reg'
	else:
		Bins = bytearray()
		RegionFile = 'Temp.reg'

	if RegionSize != 0:
		if len (Bins) > RegionSize:
			raise Exception ('file %s size (0x%x) is bigger than region size (0x%x)!' % (ImageFile, len(Bins), RegionSize))
		if len (Bins) < RegionSize:
			Bins.extend ('\xff' * (RegionSize - len(Bins)))

	fo = open (RegionFile, 'wb')
	fo.write (Bins)
	fo.close()
	return RegionFile, len (Bins)

def GetPayloadList (Payloads):
	pld_tmp  = dict()
	pld_lst  = []
	pld_num  = len(Payloads)

	for idx, pld in enumerate(Payloads):
		items    = pld.split(':')
		item_cnt = len(items)
		pld_tmp['file'] = items[0]

		if item_cnt > 1 and items[1].strip():
			pld_tmp['align'] = int(items[1])
		else:
			pld_tmp['align'] = 4

		pld_lst.append(dict(pld_tmp))

	return pld_lst


class IasHeader(Structure):
	MAGIC             = 'ipk.'
	SIGNATURE_PRESENT = 0x100  # RSA signature present
	PUBKEY_PRESENT    = 0x200  # Public Key present
	_pack_ = 1
	_fields_ = [
		('Magic',    ARRAY(c_char, 4)),  # Identifies structure (acts as valid flag)
		('ImageType',        c_uint32),  # Image and compression type
		('Version',          c_uint32),  # Header version
		('DataLength',       c_uint32),  # Size of payload (data) in image
		('DataOffset',       c_uint32),  # Offset to payload data from header
		('UncompressedLen',  c_uint32),  # Uncompressed data length
		('HeaderCrc',        c_uint32)   # CRC-32C over entire header
	]

def HexDump (Bins, Offset, Size, Lines, IndentSize = 0):
	Idx = 0
	Str = ""
	for ch in Bins[Offset:Offset+Size]:
		if (Idx % 16) == 0:
			Str += " " * IndentSize + "|  0x%-3x:" % Idx
		Str += " %02x " % ch
		Idx += 1
		Str += "|\n" if (Idx % 16) == 0 else ""

	if (Idx % 16) != 0:
		Str += "    " * (16 - Idx % 16) + "|\n"

	Lines.append (Str)

def GetPubkeyFromIas (IasImage):
	# Read IasImage
	with open(IasImage, 'rb') as input_file:
		data = bytearray(input_file.read())

	# Check header
	hdr = IasHeader.from_buffer(data)
	if hdr.Magic != IasHeader.MAGIC:
		raise Exception ("Invalid IAS magic '%s' in file %s!" % (hdr.Magic, IasImage))

	if not (hdr.ImageType & IasHeader.SIGNATURE_PRESENT):
		raise Exception ("IAS signature doesn't exist!")

	if not (hdr.ImageType & IasHeader.PUBKEY_PRESENT):
		raise Exception ("IAS public key doesn't exist!")

	SigOffset = hdr.DataOffset + hdr.DataLength + sizeof (c_uint32)
	KeyOffset = ((SigOffset + 255) & ~255) + 256
	Key = data[KeyOffset:KeyOffset+sizeof(c_uint32)+256+sizeof(c_uint32)]

	#Lines = []
	#HexDump (Key, 0, 264, Lines)
	#print ''.join(Lines)
	return Key

# ===============================================
# SBL POD structures
# ===============================================
class RSA2048SHA256_PUBKEY(Structure):
	VERIFICATION_LIB_SIGNATURE = '$IPP'
	_pack_ = 1
	_fields_ = [
		('Signature',   c_uint32),
		('PubKey',      ARRAY(c_uint8, 256)),
		('PubKeyExp',   c_uint32),
		]

class RSA3072SHA384_PUBKEY(Structure):
	VERIFICATION_LIB_SIGNATURE = '$IPP'
	_pack_ = 1
	_fields_ = [
		('Signature',   c_uint32),
		('PubKey',      ARRAY(c_uint8, 384)),
		('PubKeyExp',   c_uint32),
		]

AUTH_TYPE_KEY_SIZE = {
	"RSA2048"     : sizeof(RSA2048SHA256_PUBKEY),
	"RSA3072"     : sizeof(RSA3072SHA384_PUBKEY),
}

AUTH_TYPE_SIG_SIZE = {
	"RSA2048"     : 256,
	"RSA3072"     : 384,
}

AUTH_TYPE_VALUE = {
	""            : 0,
	"NONE"        : 0,
	"SHA2_256"    : 1,
	"SHA2_384"    : 2,
	"RSA2048"     : 3,
	"RSA3072"     : 4,
	"IAS"         : 5,
}

def GetKeySize (AuthTypeStr):
	return AUTH_TYPE_KEY_SIZE[AuthTypeStr]

def GetSigSize (AuthTypeStr):
	return AUTH_TYPE_SIG_SIZE[AuthTypeStr]

def GetSigKeySizeByTypeStr (AuthTypeStr):
	return AUTH_TYPE_KEY_SIZE[AuthTypeStr] + AUTH_TYPE_SIG_SIZE[AuthTypeStr]

def GetAuthTypeStr (AuthType):
	AuthValueType = dict([(Value, Type) for Type, Value in AUTH_TYPE_VALUE.items()]) 
	return AuthValueType[AuthType]

def GetSigKeySizeByTypeValue (AuthType):
	AuthTypeStr = GetAuthTypeStr (AuthType)
	if AuthTypeStr != 'RSA2048' and AuthTypeStr != 'RSA3072':
		return 0
	return GetSigKeySizeByTypeStr (AuthTypeStr)


class SblPodHeader(Structure):
	SBL_POD_HEADER_SIGNATURE = 'SPOD'
	POD_HEADER_FLAGS = {
		"IMAGE"        : 0x00000001,
		"COMPRESSED"   : 0x00000002,
	}

	_pack_ = 1
	_fields_ = [
		('Signature',   ARRAY(c_char, 4)), # Identifies structure
		('Version',     c_uint16),         # Header version
		('DataOffset',  c_uint16),         # Offset of payload (data) from header in byte
		('DataSize',    c_uint32),         # Size of payload (data) in byte
		('AuthType',    c_uint8),          # Refer AUTH_TYPE_VALUE: 0 - "NONE"; 2- "RSA2048SHA256"; 4 - RSA3072SHA384
		('ImageType',   c_uint8),          #  03 - POD_TYPE_CLASSIC //Files: cmdline, bzImage, initrd, acpi, firmware1, firmware2, ...
										   #  04 - POD_TYPE_MULTIBOOT // cmdline1, elf1, cmdline2, elf2, ...
		('Flag',        c_uint8),          # #define SBL_POD_FLAG_IMAGE BIT0  #define SBL_POD_FLAG_COMPRESSED  - BIT1
		('EntryCount',  c_uint8),          # Number of entry in the header
		]

	def __init__(self):
		self.Signature  = self.SBL_POD_HEADER_SIGNATURE
		self.Version    = 1
		self.DataOffset = 0
		self.DataSize   = 0
		self.AuthType   = 0
		self.ImageType  = 0
		self.Flag       = 0
		self.EntryCount = 0
		self.PodEntrys  = []

	def SetFlag(self, Flag):
		self.Flag  |= Flag

	def SetDataOffset(self, Offset):
		self.DataOffset = DataOffset

	def AddPodEntry(self, PodEntry):
		self.PodEntrys.append(PodEntry)
		self.EntryCount += 1

	def GetHeaderSize (self):
		HeaderSize = sizeof (self)
		for x in self.PodEntrys:
			HeaderSize += sizeof(SblPodEntry) + x.HashSize
		return HeaderSize

	def WritePodHeader (self, OutFile):
		Bins = bytearray()
		Bins.extend (self)
		for x in self.PodEntrys:
			Bins.extend (x)
			if x.HashSize:
				Bins.extend (x.HashData)

		fo = open(OutFile,'wb')
		fo.write (Bins)
		fo.close()

	def DumpPodHeader (self):
		print "Dumping SBL pod header:"
		print "Signature : 0x%x" % self.Signature
		print "Version   : 0x%x" % self.Version
		print "DataOffset: 0x%x" % self.DataOffset
		print "DataSize  : 0x%x" % self.DataSize
		print "AuthType  : 0x%x (1-sh256;2-sha384;3-rsa2048; 4-rsa3072)" % self.AuthType
		print "ImageType : 0x%x" % self.ImageType
		print "Flag      : 0x%x (Bit0-verify header together with pld" % self.Flag
		print "EntryCount: 0x%x" % self.EntryCount




class SblPodEntry(Structure):
	POD_ENTRY_NAME_HDR = '$HDR'
	POD_ENTRY_NAME_PLD = '$PLD'


	_pack_ = 1
	_fields_ = [
		('Name',        ARRAY(c_char, 4)),   # SBL pod entry name
		('Offset',      c_uint32),   # Component offset in byte from the payload (data)
		('Size',        c_uint32),   # Region/Component size in byte
		('Reserved',    c_uint8),    # reserved
		('Alignment',   c_uint8),    # This image need to be loaded to memory  in (1 << Alignment) address
		('AuthType',    c_uint8),    # Refer AUTH_TYPE_VALUE: 0 - "NONE"; 1- "SHA2_256";  2- "RSA2048SHA256"; 3- "SHA2_384"; 4 - RSA3072SHA384
		('HashSize',    c_uint8)     # Hash data size, it could be image hash or public key hash
		]

	def __init__(self):
		self.Name       = '    '
		self.Offset     = 1
		self.Size       = 0
		self.Reserved   = 0
		self.Alignment  = 0
		self.AuthType   = 0
		self.HashSize   = 0
		self.HashData   = bytearray()

	def UpdateHashData (self, AuthTypeStr, PrivKeyFile, ImageFile):
		Data = bytearray()
		if AuthTypeStr == "NONE" or AuthTypeStr == "":
			print "    No authentication"
		elif AuthTypeStr == "SHA2_256":
			fi = open(ImageFile,'rb')
			di = fi.read()
			fi.close()
			Data = hashlib.sha256(di).digest()
		elif AuthTypeStr == "RSA2048":
			di = GenPubKey (PrivKeyFile, "Key.pub")
			Data = hashlib.sha256(di).digest()
		elif AuthTypeStr == "IAS":
			di = GetPubkeyFromIas (ImageFile)
			Data = hashlib.sha256(di).digest()
		else:
			raise Exception ("Unsupport AuthTupe '%s' !" % AuthTypeStr)

		self.HashData.extend(Data)
		self.HashSize = len (Data)
		if self.HashSize:
			print "    HashSize = 0x%x" % self.HashSize


def GetRegionList ():
	RegionList = [
		#  Name      | Image File |    compAlg  | AuthType | Key File                   | Region Size
		('$HDR',               '',          '',   'RSA2048', 'TestSigningPrivateKey.pem',        0), # key used to sign region header
		('FB  ',  'iasimage2.bin',          '',       'IAS',                          '', 0x300000), # IAS image
		#('PRES',   'podimage.bin',          '',       'POD',                          '', 0x300000), # POD image
		('TST0',      'Test1.bin',     'Dummy',      'NONE',                          '',   0x3000), # Single image, Dummy LZ header, no verification
		('MAC1',      'Test2.bin',       'Lz4',          '',                          '',   0x3000), # Single image, Lz4 compressed,  no verification
		('MAC2',      'Test2.bin',       'Lz4',   'RSA2048', 'TestSigningPrivateKey.pem',   0x3000), # Single image, Lz4 compressed,  using RSA 2048 to verify
		('FIL1',      'Test3.bin',      'Lzma',  'SHA2_256',                          '',        0), # Single image, Lzmz compressed. using sh256 to verify.
		('TST1',               '',          '',      'NONE',                          '',   0x1000), # empty region
	]
	return RegionList



class Build(object):
	def __init__(self):
		self._InputDir        = os.path.dirname (os.path.realpath(__file__))
		self._OutputDir       = os.path.dirname (os.path.realpath(__file__))
		self._RegionBin       = bytearray()

	def AddRegionImage (self, RegFile):
		fi = open (RegFile, "rb")
		di = fi.read()
		fi.close()
		self._RegionBin.extend (di)

	def RegionOffsetAdjust (self, RegOffset, RegionSize):
		# if RegionSize != 0, means this region need be updated seperatedly.
		# So make sure it is in 4KB aligned address.
		RegSizeAdjust  = 0
		if RegionSize != 0:
			RegSizeAdjust = ((RegOffset + 0xFFF) & 0xFFFFF000) - RegOffset
			if RegSizeAdjust != 0:
				self._RegionBin.extend ('\xff' * RegSizeAdjust)
		return RegSizeAdjust

	def CheckInput (self, Name, ImageFile, AuthType, KeyFile, RegionSize):
		if (ImageFile == '') and (RegionSize == 0):
			raise Exception ("Unknow region size for '%s'!" % Name)

		if ImageFile != '':
			FilePath = os.path.join(self._InputDir, ImageFile)
			if not os.path.exists(FilePath):
				raise Exception ("Not found file '%s'!" % FilePath)

		if KeyFile != '':
			FilePath = os.path.join(self._InputDir, KeyFile)
			if not os.path.exists(FilePath):
				raise Exception ("Not found file '%s'!" % FilePath)

		if AuthType == "RSA2048" or AuthType == "RSA3072":
			if KeyFile == '':
				raise Exception ("Key file is not provided for RSA auth type :%s!" % Name)

	def GenSubRegions (self, args):
		OutFile = args.OutFile
		RegionList = GetRegionList ()
		RegOffset  = 0
		PodHeader  = SblPodHeader()
		for Idx, (_Name, _ImageFile, _CompAlg, _AuthType, _KeyFile, _RegionSize) in enumerate(RegionList):
			if _Name == SblPodEntry.POD_ENTRY_NAME_HDR:
				continue
			print "\n%s:" % _Name
			#print "File = %s, CompAlg = %s, Type=%s, Key=%s, Size=0x%x" % (_ImageFile, _CompAlg, _AuthType, _KeyFile, _RegionSize)
			self.CheckInput (_Name, _ImageFile, _AuthType, _KeyFile, _ImageFile)
			KeyFile = os.path.join(self._InputDir, _KeyFile)

			# Generate region data
			FinalFile = ''
			if _ImageFile != '':
				ImageFile = os.path.join(self._InputDir, _ImageFile)
				if _AuthType == "IAS":
					# Take IAS raw image as final file in region
					FinalFile = ImageFile
				elif _AuthType == 'RSA2048' or _AuthType == 'RSA3072':
					CompressedFile = compress (ImageFile, _CompAlg)
					FinalFile = GenSignedFile (CompressedFile, '', KeyFile, _AuthType)
				else:
					FinalFile = compress (ImageFile, _CompAlg)
			RegFile, RegSize   = GenRegionFile (FinalFile, _RegionSize)
			RegOffset += self.RegionOffsetAdjust (RegOffset, _RegionSize)
			self.AddRegionImage (RegFile)

			# Generate pod entry
			Entry = SblPodEntry ()
			Entry.Name     = _Name
			Entry.AuthType = AUTH_TYPE_VALUE[_AuthType]
			Entry.Offset   = RegOffset
			Entry.Size     = RegSize
			Entry.UpdateHashData (_AuthType, KeyFile, FinalFile)

			# Add pod entry
			PodHeader.AddPodEntry (Entry)
			RegOffset += RegSize

		PodHeader.DataSize = len (self._RegionBin)
		KeyFile = ''
		for Idx, (_Name, _ImageFile, _CompAlg, _AuthType, _KeyFile, _RegionSize) in enumerate(RegionList):
			if _Name != SblPodEntry.POD_ENTRY_NAME_HDR:
				continue
			# Currently support RSA2048 only for sub regions
			Entry = SblPodEntry ()
			if _AuthType == "RSA2048":
				PodHeader.DataOffset = GetSigKeySizeByTypeStr (_AuthType)
			else:
				raise Exception ("For Regions, now only RSA2048!")

			KeyFile = _KeyFile
			PodHeader.AuthType    = AUTH_TYPE_VALUE[_AuthType]
			PodHeader.DataOffset += PodHeader.GetHeaderSize()
			# Make the header 4K aligned
			PodHeader.DataOffset = (PodHeader.DataOffset + 0xFFF) & ~0xFFF
			break

		PodHeader.WritePodHeader(OutFile)
		AuthValueType = dict([(Value, Type) for Type, Value in AUTH_TYPE_VALUE.items()]) 
		SignedFile = GenSignedFile (OutFile, '', KeyFile, AuthValueType[PodHeader.AuthType])
		bins = bytearray(open(SignedFile, 'rb').read())
		if PodHeader.DataOffset - len (bins) > 0:
			bins.extend ('\xff' * (PodHeader.DataOffset - len (bins)))
		bins.extend (self._RegionBin)
		open (OutFile, 'wb').write (bins)

		print "Generate subregion image %s successfully" % args.OutFile
		if args.VerbBins:
			PodLayoutLines = DumpPodFile(args.OutFile)
			print '%s' % PodLayoutLines
		elif args.Verbose:
			PodLayoutLines = DumpPodFile(args.OutFile, False)
			print '%s' % PodLayoutLines

	# Generate signed pod image
	# input:
	#   File list, with alignment (optional)
	#   Private key file in PEM format.
	#   AuthType, should match with private key.
	#   Compressed alg (optional)
	#   ImageType (optional)
	# output:
	#   generated output file
	def GenPodImage (self, args):
		print('Creating pod image with %d files' % len(args.file))

		# check parameters
		if args.AuthType != 'RSA2048' and args.AuthType != 'RSA3072':
			raise ("PodImage only supports RSA (2048 or 3072) signing")

		RegOffset  = 0
		PodHeader  = SblPodHeader()
		PldList    = GetPayloadList (args.file)
		for idx, pld in enumerate(PldList):
			try:
				with open(pld['file'], 'rb') as InputFile:
					di = InputFile.read()
			except IOError:
				raise ('Error: No such file or directory: %s' % pld['file'])

			# Make sure 4-byte aligned
			PadSize = ((RegOffset + 3) & ~3) - RegOffset
			if PadSize != 0:
				self._RegionBin.extend ('\xff' * PadSize)
				RegOffset += PadSize
			self._RegionBin.extend (di)

			# Generate pod entry
			Entry = SblPodEntry ()
			Entry.Name      = 'PODI'
			Entry.AuthType  = 0
			Entry.Offset    = RegOffset
			Entry.Alignment = pld['align']
			Entry.Size      = len (di)
			Entry.HashSize  = 0

			# Add pod entry
			PodHeader.AddPodEntry (Entry)
			RegOffset += Entry.Size

		PodHeader.AuthType   = AUTH_TYPE_VALUE[args.AuthType]
		PodHeader.DataOffset = PodHeader.GetHeaderSize()
		PodHeader.DataSize   = len (self._RegionBin)

		# Get payload content
		PodHeader.Flag  |= PodHeader.POD_HEADER_FLAGS['IMAGE']
		if args.CompAlg != '':
			PodHeader.Flag |= PodHeader.POD_HEADER_FLAGS['COMPRESSED']
			open ("PldRaw.bin", 'wb').write (self._RegionBin)
			CompressedFile  = compress ("PldRaw.bin", args.CompAlg)
			pldbins = open (CompressedFile, 'rb').read()
		else:
			pldbins = self._RegionBin

		# Get pod header content
		PodHeader.WritePodHeader("Final.bin")
		open ("Final.bin", 'ab').write (pldbins)
		GenSignedFile ("Final.bin", args.OutFile, args.PrivKey, args.AuthType)
		os.remove("Final.bin")

		print "Generate pod image %s successfully" % args.OutFile
		if args.VerbBins:
			PodLayoutLines = DumpPodFile(args.OutFile)
			print '%s' % PodLayoutLines
		elif args.Verbose:
			PodLayoutLines = DumpPodFile(args.OutFile, False)
			print '%s' % PodLayoutLines

def ExtractPodFile (args):
	if not os.path.exists(args.ImageFile):
		raise Exception("No file '%s' found !" % args.ImageFile)
		return

	fi = open (args.ImageFile, 'rb')
	PodBins = bytearray(fi.read())
	fi.close()

	PodHeader = SblPodHeader.from_buffer (PodBins)
	if PodHeader.Signature != SblPodHeader.SBL_POD_HEADER_SIGNATURE:
		print "NOT pod image by checking the signature"
		return

	AuthValueType = dict([(Value, Type) for Type, Value in AUTH_TYPE_VALUE.items()]) 
	LzHdr = LzHeader.from_buffer (PodBins, PodHeader.DataOffset)
	if PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['COMPRESSED']:
		fo = open ("Pld.lz", 'wb')
		fo.write (PodBins[PodHeader.DataOffset:PodHeader.DataOffset + LzHdr.CompressedLen + sizeof(LzHeader)])
		fo.close()
		OriPldFile = Decompress ("Pld.lz")
		PldRaw = open (OriPldFile, 'rb').read()
	else:
		PldRaw = PodBins[PodHeader.DataOffset:PodHeader.DataOffset + PodHeader.DataSize]

	Offset = sizeof(SblPodHeader)
	for idx in xrange (PodHeader.EntryCount):
		Entry   = SblPodEntry.from_buffer (PodBins, Offset)
		FileBin = PldRaw[Entry.Offset:Entry.Offset + Entry.Size]
		open ("Pld%d.bin" % idx, 'wb').write(FileBin)
		print "Pld%d.bin is extracted." % idx

		if not (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['IMAGE']):
			# POD Subregion image
			FilePodHeader = SblPodHeader.from_buffer (FileBin)
			FileIasHeader = IasHeader.from_buffer (FileBin)
			FileLzHeader  = LzHeader.from_buffer (FileBin)
			if FilePodHeader.Signature == SblPodHeader.SBL_POD_HEADER_SIGNATURE:
				print "    Pod image, saved to File%s.bin" % idx
				if FilePodHeader.Flag & PodHeader.POD_HEADER_FLAGS['COMPRESSED']:
					FileLzHdr = LzHeader.from_buffer (FileBin, FilePodHeader.DataOffset)
					PldSize = FilePodHeader.DataOffset + LzHdr.CompressedLen + sizeof(LzHeader)
				else:
					PldSize = FilePodHeader.DataOffset + FilePodHeader.DataSize
				PldSize += GetSigKeySizeByTypeValue(FilePodHeader.AuthType)
			elif FileIasHeader.Magic == IasHeader.MAGIC:
				print "    IAS image, saved to File%s.bin" % idx
				SigOffset  = FileIasHeader.DataOffset + FileIasHeader.DataLength
				print "    0x%x" % FileIasHeader.DataOffset
				print "    0x%x" % FileIasHeader.DataLength
				print "    0x%x" % SigOffset
				SigOffset = ((SigOffset + 255) & ~255) + 256
				PldSize    = SigOffset + sizeof(c_uint32) + 256 + sizeof(c_uint32)
				print "    0x%x" % SigOffset
				print "    0x%x" % PldSize
			elif FileLzHeader.Signature == "LZDM" or FileLzHeader.Signature == "LZMA" or FileLzHeader.Signature == "LZ4 ":
				print "    %s Compressed image, saved as File%s.bin" % (FileLzHeader.Signature, idx)
				PldSize = FileLzHeader.CompressedLen + sizeof(FileLzHeader) + GetSigKeySizeByTypeValue(Entry.AuthType)
			else:
				print "    Unsupported image"
				PldSize = 0

			if PldSize:
				FileBin = FileBin[0:PldSize]
				open ("File%d.bin" % idx, 'wb').write(FileBin)

		Offset += sizeof (SblPodEntry) + Entry.HashSize


def DumpPodFile (PodFile, DispBinary = True):
	if not os.path.exists(PodFile):
		raise Exception("No file '%s' found !" % PodFile)
		return

	fi = open (PodFile, 'rb')
	PodBins = bytearray(fi.read())
	fi.close()

	PodHeader   = SblPodHeader.from_buffer (PodBins)
	HeaderFlags  = 'IMG  ' if (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['IMAGE']) else '     '
	HeaderFlags += 'LZ   ' if (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['COMPRESSED']) else '     '

	AuthValueType = dict([(Value, Type) for Type, Value in AUTH_TYPE_VALUE.items()]) 
	PodLayoutLines = [
		"\nPod Layout information:\n"\
		"\t+------------------------------------------------------------------------+\n" \
		"\t|                              POD  Header                               |\n" \
		"\t+------------------------------------------------------------------------+\n" \
		"\t|  AuthType      = %-14s         ImageType   = 0x%-2x             |\n" \
		"\t|  EntryCount    = 0x%-2x                   Flag        = %s       |\n" \
		"\t|  PayloadOffset = 0x%-7x              PayloadSize = 0x%-7x        |\n" \
		% (AuthValueType[PodHeader.AuthType], PodHeader.ImageType, \
		PodHeader.EntryCount, HeaderFlags,\
		PodHeader.DataOffset, PodHeader.DataSize)]

	if DispBinary:
		PodLayoutLines.append (
			"\t+---------------------------POD Header Raw Data--------------------------+\n")
		HexDump (PodBins, 0, sizeof(SblPodHeader), PodLayoutLines, 8)

	PodLayoutLines.append (
		"\t+------------------------------------------------------------------------+\n" \
		"\t|                              POD  Entry                                |\n" \
		"\t+------------------------------------------------------------------------+\n" \
		"\t|  NAME  |   OFFSET    |    SIZE     |        AuthType       | HashSize  |\n" \
		"\t+--------+-------------+-------------+-----------------------+-----------+\n")

	Offset = sizeof(SblPodHeader)
	for idx in xrange (PodHeader.EntryCount):
		Entry   = SblPodEntry.from_buffer (PodBins, Offset)
		Offset += sizeof (SblPodEntry) + Entry.HashSize
		PodLayoutLines.append ("\t|  %s  |  0x%-7x  |  0x%-7x  |  0x%-2x(%-14s) |   0x%-3x   |\n" \
			% (Entry.Name, Entry.Offset, Entry.Size, Entry.AuthType, AuthValueType[Entry.AuthType], Entry.HashSize))

	if DispBinary:
		PodLayoutLines.append ("\t+-------------------------- POD Entry Raw Data --------------------------+\n")
		Offset = sizeof(SblPodHeader)
		for idx in xrange (PodHeader.EntryCount):
			Entry  = SblPodEntry.from_buffer (PodBins, Offset)
			EntrySize = sizeof (SblPodEntry) + Entry.HashSize
			HexDump (PodBins, sizeof(SblPodHeader) + Offset, EntrySize, PodLayoutLines, 8)
			Offset += EntrySize

	if (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['COMPRESSED']):
		PodLayoutLines.append ("\t+------------------------ Compressed payload ----------------------------+\n")
		LzHdr = LzHeader.from_buffer (PodBins, PodHeader.DataOffset)
		PodLayoutLines.append ("\t|  Signature = %-4s  CompressedLen = 0x%-6x  OriginalLen = 0x%-6x    |\n" \
			% (LzHdr.Signature, LzHdr.CompressedLen, LzHdr.UnCompressedLen))
		if DispBinary:
			HexDump (PodBins, PodHeader.DataOffset, sizeof (LzHeader), PodLayoutLines, 8)
	
	if DispBinary and PodHeader.AuthType != 0:
		if (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['IMAGE']):
			StrTitle = "POD image --------------------------+\n"
			if (PodHeader.Flag & PodHeader.POD_HEADER_FLAGS['COMPRESSED']):
				Offset = PodHeader.DataOffset + sizeof (LzHeader) + LzHdr.CompressedLen
			else:
				Offset = PodHeader.DataOffset + PodHeader.DataSize
		else:
			StrTitle = "POD header -------------------------+\n"

		PodLayoutLines.append ("\t+--------------------- Signature for %s" % StrTitle)
		SigSize = GetSigSize (AuthValueType[PodHeader.AuthType])
		HexDump (PodBins, Offset, SigSize, PodLayoutLines, 8)

		PodLayoutLines.append ("\t+-------------------- Public key for %s" % StrTitle)
		KeySize = GetKeySize (AuthValueType[PodHeader.AuthType])
		HexDump (PodBins, Offset + SigSize, KeySize, PodLayoutLines, 8)

	PodLayoutLines.append ("\t+------------------------------------------------------------------------+\n")

	return ''.join(PodLayoutLines)

def DumpPodImage (args):
	if args.Verbose:
		PodLayoutLines = DumpPodFile (args.ImageFile)
	else:
		PodLayoutLines = DumpPodFile (args.ImageFile, False)
	print '%s' % PodLayoutLines

def main():

	Parser = argparse.ArgumentParser()
	SubParser = Parser.add_subparsers(help='command')

	# Command for subregion
	CmdSubregion = SubParser.add_parser('subregion', help='create subregion', formatter_class=argparse.RawTextHelpFormatter)
	CmdSubregion.add_argument('-o', dest='OutFile', type=str, required=True, help='Subregion image output filename')
	CmdSubregion.add_argument('-k', dest='PrivKey', type=str, required=True, help='Private RSA key in PEM format to sign subregion header')
	CmdSubregion.add_argument('-v', dest='Verbose',  action="store_true", help= "Turn on verbose output")
	CmdSubregion.add_argument('-vb', dest='VerbBins',  action="store_true", help= "Turn on verbose output with binary informational messages printed")
	CmdSubregion.set_defaults(func=Build().GenSubRegions)

	# Command for pod image
	CmdPodImage = SubParser.add_parser('podimage', help='create SBL pod image', formatter_class=argparse.RawTextHelpFormatter)
	CmdPodImage.add_argument('-o', dest='OutFile',  type=str, required=True, help='Pod image output filename')
	CmdPodImage.add_argument('-k', dest='PrivKey',  type=str, required=True, help='Private key in PEM format to sign the generated pod image')
	CmdPodImage.add_argument('-a', dest='AuthType', type=str, help='The type to signing generated image, one of RSA2048 and RSA3072', default ='RSA2048')
	CmdPodImage.add_argument('-c', dest='CompAlg',  type=str, help='Compression algorithm -- one of Lzma, Lz4, no compression by default.\n', default ='')
	CmdPodImage.add_argument('-v', dest='Verbose',  action="store_true", help= "Turn on verbose output")
	CmdPodImage.add_argument('-vb', dest='VerbBins',  action="store_true", help= "Turn on verbose output with binary informational messages printed")
	CmdPodImage.add_argument('-i', dest='ImageType', help=' 1 - SBL configuration data\n 2 - Firmware update image\n 3 - Multi-file pod image\n 4 - ELF Multiboot compliant pod image\n')
	CmdPodImage.add_argument('file', nargs='+', help='File format is "filename:alignment". by default 4-byte if no ":alignment"')
	CmdPodImage.set_defaults(func=Build().GenPodImage)

	# Command for extract
	CmdExtract = SubParser.add_parser('extract', help='extract files from SBL pod image/region', formatter_class=argparse.RawTextHelpFormatter)
	CmdExtract.add_argument('-f', dest='ImageFile',  type=str, required=True, help='Pod image or region filename')
	CmdExtract.set_defaults(func=ExtractPodFile)

	# Command for display
	CmdDisplay = SubParser.add_parser('display', help='display pod image', formatter_class=argparse.RawTextHelpFormatter)
	CmdDisplay.add_argument('-f', dest='ImageFile',  type=str, required=True, help='Pod image to display')
	CmdDisplay.add_argument('-v', dest='Verbose',  action="store_true", help= "Turn on verbose output")
	CmdDisplay.set_defaults(func=DumpPodImage)

	# Parse arguments and run sub-command
	args = Parser.parse_args()
	if not 'func' in args:
		Parser.print_usage()
		sys.exit(2)
	args.func(args)

if __name__ == '__main__':
	sys.exit(main())
