#!/usr/bin/env python3
import argparse
import os
import sys
import time
import io
import struct
import hashlib
import binascii
from tqdm import tqdm
from intelhex import IntelHex

from panda import Panda
from panda.uds import UdsClient, NegativeResponseError, MessageTimeoutError
from panda.uds import SESSION_TYPE, DATA_IDENTIFIER_TYPE, ACCESS_TYPE, ROUTINE_CONTROL_TYPE, ROUTINE_IDENTIFIER_TYPE, RESET_TYPE

# md5sum of supported firmware
FW_MD5SUMS = [
  'cd66150b68fa09254e5a0a433abd9c8f',
  '7c17b61ab0a760d5c8076a4e6b89c911',
]
BOOTLOADER_ADDR = 0x3FF7000
FW_SIZE = 0x78000
START_ADDR = 0x7000
END_ADDR = 0x45FFF

def get_security_access_key(seed):
  key = 0xc541a9

  mask = struct.unpack('<I', seed.ljust(4, b'\x00'))[0] | 0x20000000
  for i in range(32):
    msb = key & 1 ^ mask & 1
    mask = mask >> 1
    key = key >> 1
    if (msb != 0):
      key = (key | msb << 0x17) ^ 0x109028

  mask = 0x55f222f9
  for i in range(32):
    msb = key & 1 ^ mask & 1
    mask = mask >> 1
    key = key >> 1
    if (msb != 0):
      key = (key | msb << 0x17) ^ 0x109028

  key = bytes([
    (key & 0xff0) >> 4,
    (key & 0xf000) >> 8 | (key & 0xf00000) >> 20,
    (key & 0xf0000) >> 16 | (key & 0xf) << 4,
  ])

  return key

def wait(uds_client):
  print("  wait .", end="")
  prev_timeout = uds_client.timeout
  uds_client.timeout = 0.1
  for _ in range(10):
    try:
      uds_client.tester_present()
      uds_client.timeout = prev_timeout
      print("")
      return
    except MessageTimeoutError:
      print(".", end="")
  raise Exception("reboot failed!")

def load_firmware_update(fw_update_file):
  print('loading firmware update ...')
  # the update file has multiple End Of File records (which is invalid)
  # so we split the intel hex update file into multiple files
  hex_strs = []
  s = ""
  with open(fw_update_file, 'r') as f:
    for l in f.readlines():
      s += l
      # end of file record
      if l.rstrip() == ':00000001FF':
        hex_strs.append(s)
        s = ""
  assert len(hex_strs) > 0, 'firmware update file has no firmware!'

  # IntelHex library doesn't like multiple Start Address records
  # so we only load the boot loader since that is what we need
  ih = IntelHex(io.StringIO(hex_strs[0]))
  for s, e in ih.segments():
    print(f'  {hex(s)}-{hex(e)}')
  return ih

def extract_firmware(uds_client, start_addr, size):
    print("start extended diagnostic session ...")
    uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)

    print("request security access seed ...")
    seed = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED)
    print(f"  seed: 0x{seed.hex()}")

    print("send security access key ...")
    key = get_security_access_key(seed)
    print(f"  key: 0x{key.hex()}")
    uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)

    print("extract firmware ...")
    print(f"  start addr: {hex(start_addr)}")
    print(f"  end addr: {hex(size-1)}")
    fw = b''
    chunk_size = 128
    for addr in tqdm(range(start_addr, size, chunk_size)):
      # for some stupid reason you can't read the last byte!
      cs = chunk_size if addr + chunk_size < size else size - addr - 1
      dat = uds_client.read_memory_by_address(addr, cs)
      assert len(dat) == cs, f'expected {cs} bytes but received {len(dat)} bytes starting at address {cs}'
      fw += dat
    fw += b'\xFF' # since we can't read the last byte, add filler byte

    return fw

def update_checksums(fw):
  for addr in [ 0x79c0, 0x79d0, 0x46000, 0x46010, 0x5b000, 0x5e000 ]:
    start = struct.unpack('<I', fw[addr:addr+4])[0]
    end = struct.unpack('<I', fw[addr+4:addr+8])[0]
    assert start < end, f"start addr {start} not less than end addr {end}"
    assert end < len(fw), f"end addr {end} not less than fw length {len(fw)}"
    crc32 = binascii.crc32(fw[start:end+1])
    cksum = struct.pack("<I", crc32)
    print(f"  {hex(start)}-{hex(end)} : {hex(crc32)} {'(no change)' if cksum == fw[addr+8:addr+12] else '(change)'}")
    fw = fw[:addr+8] + cksum + fw[addr+12:]
  return fw

def patch_firmware(fw):
  mods = [
    # hard-code EPB status (messsage not present on pre-AP since there is no ibooster)
    [0x031746, b'\x01'],
    # replace GTW_epasControlType with DAS_steeringControlType
    [0x03188e, b'\xdc'],
    # replace GTW_epasLDWEnable with DAS_steeringControlType
    [0x031970, b'\xdc'],
  ]
  for addr, val in mods:
    print(f"  {hex(addr)} : 0x{fw[addr:addr+len(val)].hex()} -> 0x{val.hex()}")
    fw = fw[:addr] + val + fw[addr+len(val):]
  return fw

def flash_bootloader(uds_client, fw, bootloader_addr):
  print("start programming session ...")
  uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  wait(uds_client)

  print("request security access seed ...")
  seed = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED)
  print(f"  seed: 0x{seed.hex()}")

  print("send security access key ...")
  key = get_security_access_key(seed)
  print(f"  key: 0x{key.hex()}")
  uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)

  for start_addr, end_addr in fw.segments():
    if start_addr < bootloader_addr:
      continue

    # note that end_addr is actually the end address + 1
    fw_slice = fw.tobinstr(start_addr, end_addr-1)
    slice_len = end_addr - start_addr

    print("request download ...")
    print(f"  start addr: {hex(start_addr)}")
    print(f"  end addr: {hex(end_addr)}")
    print(f"  data length: {hex(slice_len)}")
    block_size = uds_client.request_download(start_addr, slice_len)

    print("transfer data ...")
    print(f"  block size: {block_size}")
    chunk_size = block_size - 2
    cnt = 0
    for i in tqdm(range(0, slice_len, chunk_size)):
      cnt += 1
      uds_client.transfer_data(cnt & 0xFF, fw_slice[i:i+chunk_size])

    print("request transfer exit ...")
    uds_client.request_transfer_exit()

  print("enter bootloader ...")
  uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0x0301, struct.pack(">I", bootloader_addr))

def flash_firmware(uds_client, fw, start_addr, end_addr):
  fw_slice = fw[start_addr:end_addr+1]
  slice_len = end_addr - start_addr + 1
  start_and_length = struct.pack('>II', start_addr, slice_len)

  print("erase memory ...")
  print(f"  start addr: {hex(start_addr)}")
  print(f"  end addr: {hex(end_addr)}")
  print(f"  data length: {hex(slice_len)}")
  uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.ERASE_MEMORY, start_and_length)

  print("request download ...")
  print(f"  start addr: {hex(start_addr)}")
  print(f"  end addr: {hex(end_addr)}")
  print(f"  data length: {hex(slice_len)}")
  block_size = uds_client.request_download(start_addr, slice_len)

  print("transfer data ...")
  print(f"  block size: {block_size}")
  chunk_size = block_size - 2
  cnt = 0
  for i in tqdm(range(0, slice_len, chunk_size)):
    cnt += 1
    uds_client.transfer_data(cnt & 0xFF, fw_slice[i:i+chunk_size])

  print("request transfer exit ...")
  uds_client.request_transfer_exit()

  print("reset ...")
  wait(uds_client)
  try:
    uds_client.ecu_reset(RESET_TYPE.HARD | 0x80)
  except MessageTimeoutError:
    # supress response bit set, so timeout expected
    # (timeout is used to wait for reboot to complete)
    pass
  wait(uds_client)

  print("start extended diagnostic session ...")
  uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)

  print("request security access seed ...")
  seed = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED)
  print(f"  seed: 0x{seed.hex()}")

  print("send security access key ...")
  key = get_security_access_key(seed)
  print(f"  key: 0x{key.hex()}")
  uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)

  print("check dependencies ...")
  uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0xDC03)

  print("complete!")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('firmware-update-file', nargs='?', help='firmware update file for EPAS')
  parser.add_argument('--extract-only', action='store_true', help='extract the firmware (do not flash)')
  parser.add_argument('--restore', action='store_true', help='flash firmware without modification')
  parser.add_argument('--debug', action='store_true', help='print additional debug messages')
  parser.add_argument('--can-addr', type=int, default=0x730, help='TX CAN address for UDS')
  parser.add_argument('--can-bus', type=int, default=0, help='CAN bus number (zero based)')
  args = parser.parse_args()

  fw_update_file = getattr(args, 'firmware-update-file')
  if not fw_update_file and not args.extract_only:
    parser.error('either firmware-update-file or --extract-only must be specified')

  if fw_update_file:
    fw_update = load_firmware_update(fw_update_file)

  panda = Panda()
  panda.set_safety_mode(Panda.SAFETY_ALLOUTPUT)
  uds_client = UdsClient(panda, args.can_addr, bus=args.can_bus, timeout=1, debug=args.debug)

  os.chdir(os.path.dirname(os.path.realpath(__file__)))
  for fw_md5sum in FW_MD5SUMS:
    if os.path.exists(f"{fw_md5sum}.bin"):
      break
  else:
    fw_md5sum = None

  if args.extract_only or not fw_md5sum:
    fw = extract_firmware(uds_client, 0, FW_SIZE)
    md5 = hashlib.md5(fw).hexdigest()
    fw_bin_fn = f'{md5}.bin'
    print(f"  file name: {fw_bin_fn}")
    with open(fw_bin_fn, "wb") as f:
      f.write(fw)
  else:
    fw_bin_fn = f'{fw_md5sum}.bin'
    print("load firmware ...")
    print(f"  file name: {fw_bin_fn}")
    with open(fw_bin_fn, "rb") as f:
      fw = f.read()
    md5 = hashlib.md5(fw).hexdigest()

  assert len(fw) == FW_SIZE, f'expected {FW_SIZE} bytes of firmware but got {len(fw)} bytes'
  assert md5 in FW_MD5SUMS, f'expected md5sum of firmware to be in {FW_MD5SUMS} but found {md5}'
  fw_bin_mod_fn = f'{md5}.modified.bin'

  if not args.restore:
    print("modify firmware ...")
    fw = patch_firmware(fw)
    print("update checksums ...")
    fw = update_checksums(fw)
    print(f"  file name: {fw_bin_mod_fn}")
    with open(fw_bin_mod_fn, "wb") as f:
      f.write(fw)

  if args.extract_only:
    sys.exit(0)

  flash_bootloader(uds_client, fw_update, BOOTLOADER_ADDR)
  flash_firmware(uds_client, fw, START_ADDR, END_ADDR)
