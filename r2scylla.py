import argparse
from ctypes import *
from ctypes.wintypes import *
import os

class PyScylla:

  scylla_dll_path = '{}\\lib\\Scylla.dll'.format(os.path.dirname(os.path.realpath(__file__)))
  
  def __init__(self):
    self.scylla = windll.LoadLibrary(self.scylla_dll_path)
  
  def run_gui(self, pid, entry_point, mod=0):
    c_pid = c_ulong(pid)
    c_entry_point = c_ulong(entry_point)
    self.scylla.ScyllaStartGui(c_pid, mod, c_entry_point)
	
  def dump_process(self, pid, file_to_dump, image_base, entry_point, file_result):
    c_pid = c_ulong(pid)
    c_entry_point = c_ulong(entry_point)
    c_image_base = c_ulong(image_base)
    c_file_to_dump = LPCWSTR(file_to_dump)
    c_file_result = LPCWSTR(file_result)
    self.scylla.ScyllaDumpProcessW(c_pid, c_file_to_dump, c_image_base, c_entry_point, c_file_result)

  def iat_search(self, pid, search_start, advanced_search=True):
    iat_start = c_ulong()
    iat_size = c_ulong()
    c_pid = c_ulong(pid)
    c_search_start = c_ulong(search_start)
    self.scylla.ScyllaIatSearch(c_pid, byref(iat_start), byref(iat_size), c_search_start, advanced_search)
    return iat_start.value, iat_size.value
	
  def iat_auto_fix(self, iat_addr, iat_size, pid, dump_file, iat_fix_file):
    c_iat_addr = c_ulong(iat_addr)
    c_iat_size = c_ulong(iat_size)
    c_pid = c_ulong(pid)
    c_dump_file = LPCWSTR(dump_file)
    c_iat_fix_file = LPCWSTR(iat_fix_file)
    self.scylla.ScyllaIatFixAutoW(c_iat_addr, c_iat_size, c_pid, c_dump_file, c_iat_fix_file)
	
  def rebuild_file(self, file_to_rebuild, remove_dos_stub=False, update_pe_header_checksum=True, createa_backup=False):
    c_file_to_rebuild = LPCWSTR(file_to_rebuild)
    self.scylla.ScyllaRebuildFileW(c_file_to_rebuild, remove_dos_stub, update_pe_header_checksum, createa_backup)
	
	
class R2Scylla:

  def __init__(self):
    self.scylla = PyScylla()
	
  def full_dump(self, args):
    pid = int(args.pid, 16)
    entry_point = int(args.oep, 16)
    image_base = int(args.base_address, 16)
    file_to_dump = args.binary_path
    file_result = '{}_dumped.exe'.format(args.binary_path.rsplit('.', 1)[0])
    print 'Dumping process...'
    self.scylla.dump_process(pid, file_to_dump, image_base, entry_point, file_result)
    print 'Searching IAT...'
    iat_start, iat_size = self.scylla.iat_search(pid, entry_point)
    print 'Fixing IAT...'
    self.scylla.iat_auto_fix(iat_start, iat_size, pid, file_result, file_result)
    print 'Rebuilding PE...'
    self.scylla.rebuild_file(file_result)
    print 'Dumped process {} to {}'.format(pid, file_result)

  def dump_process(self, args):
    print 'Dumping process...'
    pid = int(args.pid, 16)
    entry_point = int(args.oep, 16)
    image_base = int(args.base_address, 16)
    self.scylla.dump_process(pid, args.file, image_base, entry_point, args.output_file)
    print 'Dumped process {} to {}'.format(pid, args.output_file)
	
  def iat_search(self, args):
    print 'Searching IAT...'
    pid = int(args.pid, 16)
    start = int(args.start, 16)
    iat_start, iat_size = self.scylla.iat_search(pid, start)
    print 'IAT found at 0x%x with size %d' % (iat_start, iat_size)
	
  def iat_auto_fix(self, args):
    print 'Fixing IAT...'
    iat_addr = int(args.iat_address, 16)
    iat_size = int(args.iat_size)
    pid = int(args.pid, 16)
    self.scylla.iat_auto_fix(iat_addr, iat_size, pid, args.dumped_pe, args.output_file)
    print 'IAT from {} fixed into {}'.format(args.dumped_pe, args.output_file)
	
  def rebuild_file(self, args):
    print 'Rebuilding PE...'
    self.scylla.rebuild_file(args.dumped_file, args.remove_dos_stub, args.update_header_checksum, args.create_backup)
    print 'PE {} rebuilt'.format(args.dumped_file)
	
  def add_full_dump_args(self, subparser):
    fulldump = subparser.add_parser('fulldump', help='Dumps the process, fixes IAT and rebuilds PE')
    fulldump.add_argument('pid', help='This argument specifies the process id (PID) of the debugged process that is going to be dumped')
    fulldump.add_argument('oep', help='This argument specifies the original entry point (OEP) of the PE')
    fulldump.add_argument('base_address', help='This argument specifies the base address')
    fulldump.add_argument('binary_path', help='This argument specifies the path of the binary that is going to be dumped')
    fulldump.set_defaults(func=self.full_dump)
	
  def add_iat_search_args(self, subparser):
    searchiat = subparser.add_parser('searchiat', help='Searches the IAT within the specified process')
    searchiat.add_argument('pid', help='This argument specifies the process id (PID) of the debugged process')
    searchiat.add_argument('start', help='This argument specifies the start address from which the IAT search will start')
    searchiat.set_defaults(func=self.iat_search)
	
  def add_dump_process_args(self, subparser):
    dumpproc = subparser.add_parser('dumpproc', help='Dumps the specified process to a file')
    dumpproc.add_argument('pid', help='This argument specifies the process id (PID) of the debugged process')
    dumpproc.add_argument('file', help='This argument specifies the file of the PE that will be dumped')
    dumpproc.add_argument('base_address', help='This argument specifies the base address')
    dumpproc.add_argument('oep', help='This argument specifies the original entry point (OEP) of the PE')
    dumpproc.add_argument('output_file', help='This argument speficies the file where the process will be dumped')
    dumpproc.set_defaults(func=self.dump_process)
	
  def add_iat_fix_args(self, subparser):
    iatfix = subparser.add_parser('iatfix', help='Fixes the IAT of a given PE')
    iatfix.add_argument('iat_address', help='This argument specifies the address of the IAT')
    iatfix.add_argument('iat_size', help='This argument specifies the size of the IAT')
    iatfix.add_argument('pid', help='This argument specifies the process id (PID) of the debugged process')
    iatfix.add_argument('dumped_pe', help='This argument specifies the full path to the file whose IAT has to be fixed')
    iatfix.add_argument('output_file', help='This argument specifies the file where the PE with the fixed IAT will be written')
    iatfix.set_defaults(func=self.iat_auto_fix)
	
  def add_rebuild_args(self, subparser):
    rebuild = subparser.add_parser('rebuild', help='Rebuilds the given PE')
    rebuild.add_argument('dumped_file', help='This argument specifies the full path of the PE to be rebuilt')
    rebuild.add_argument('remove_dos_stub', help='This argument specifies whether the DOS stub should be removed or not (True, False)')
    rebuild.add_argument('update_header_checksum', help='This argument specifies whether the PE header checksum should be updated or not (True, False)')
    rebuild.add_argument('create_backup', help='This argument specifies whether a backup of the PE should be created or not (True, False)')
    rebuild.set_defaults(func=self.rebuild_file)
	
  def parse_args(self):
    parser = argparse.ArgumentParser(description='This is a radare2 plugin for Scylla')
    subparser = parser.add_subparsers(help='Commands')
    self.add_full_dump_args(subparser)
    self.add_iat_search_args(subparser)
    self.add_dump_process_args(subparser)
    self.add_iat_fix_args(subparser)
    self.add_rebuild_args(subparser)
    args = parser.parse_args()
    args.func(args)

	
if __name__ == '__main__':
    r2scylla = R2Scylla()
    r2scylla.parse_args()
	
