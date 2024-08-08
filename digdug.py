#!/usr/bin/env python3
import argparse
from os import path, stat
from random import choice
import string
import sys
import struct
import io


def gen_random_bytes(desired_size):
    # Generates a random key of desired_size length
    return bytes(''.join(choice(string.ascii_uppercase + string.ascii_lowercase)
                         for _ in range(desired_size)), 'ascii')


def build_padding(desired_size, dictionary_file):
    # read in words dictionary
    sizeof_dictionary_file = stat(dictionary_file).st_size

    # Final size is approximate as we're converting a float to an int
    multiplier = int(desired_size / sizeof_dictionary_file)

    with open(dictionary_file, 'rb') as dictionary:
        words = dictionary.read()

    # Increase the size of dictionary to our desired size
    multiplied_words = words * int(multiplier + 1)

    # Get the exact size requested
    final_words = multiplied_words[:desired_size]

    return final_words


def get_file_size(my_file):
    my_file_stats = stat(my_file)
    my_file_len = my_file_stats.st_size
    return my_file_len


'''The next four functions are adapted from SigThief
    https://github.com/secretsquirrel/SigThief
'''


def gather_file_info_win(binary):
    """
    Parse binary and gather metadata
    """
    flItms = {}
    binary = open(binary, 'rb')
    binary.seek(int('3C', 16))
    flItms['buffer'] = 0
    flItms['JMPtoCodeAddress'] = 0
    flItms['dis_frm_pehdrs_sectble'] = 248
    flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
    # Start of COFF
    flItms['COFF_Start'] = flItms['pe_header_location'] + 4
    binary.seek(flItms['COFF_Start'])
    flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
    binary.seek(flItms['COFF_Start'] + 2, 0)
    flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
    flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
    binary.seek(flItms['COFF_Start'] + 16, 0)
    flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
    # End of COFF
    flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

    # if flItms['SizeOfOptionalHeader']:
    # Begin Standard Fields section of Optional Header
    binary.seek(flItms['OptionalHeader_start'])
    flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
    flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
    flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                      binary.read(4))[0]
    flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
    flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
    flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
    if flItms['Magic'] != 0x20B:
        flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
    # End Standard Fields section of Optional Header
    # Begin Windows-Specific Fields of Optional Header
    if flItms['Magic'] == 0x20B:
        flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
    else:
        flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
    flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                          binary.read(2))[0]
    flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
    flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfImageLoc'] = binary.tell()
    flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
    flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
    flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
    flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
    flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
    if flItms['Magic'] == 0x20B:
        flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

    else:
        flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
    flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
    flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
    # End Windows-Specific Fields of Optional Header
    # Begin Data Directories of Optional Header
    flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
    # ImportTable SIZE|LOC
    flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
    flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
    flItms['CertTableLOC'] = binary.tell()
    flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
    flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
    binary.close()
    return flItms


def copy_cert(exe):
    flItms = gather_file_info_win(exe)

    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert


def write_cert(cert, exe, output_file):
    flItms = gather_file_info_win(exe)

    with open(output_file, 'ab') as f:
        f.seek(0)
        f.seek(flItms['CertTableLOC'], 0)
        f.write(struct.pack("<I", len(open(exe, 'rb').read())))
        f.write(struct.pack("<I", len(cert)))
        f.seek(0, io.SEEK_END)
        f.write(cert)

    print('Successfully added signature to ' + output_file + '!')


def check_sig(exe):
    flItms = gather_file_info_win(exe)
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        # source exe is not signed
        return False
    else:
        # source exe is signed
        return True


def main():
    banner = """
  ██████╗ ██╗ ██████╗     ██████╗ ██╗   ██╗ ██████╗     
  ██╔══██╗██║██╔════╝     ██╔══██╗██║   ██║██╔════╝     
  ██║  ██║██║██║  ███╗    ██║  ██║██║   ██║██║  ███╗    
  ██║  ██║██║██║   ██║    ██║  ██║██║   ██║██║   ██║    
  ██████╔╝██║╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝    
  ╚═════╝ ╚═╝ ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝
"""
    # Parse our arguments
    parser = argparse.ArgumentParser(description='Inflate an executable with words')
    parser.add_argument('-i', '--input', type=str, required=True,
                        help="Input file to increase size")
    parser.add_argument('-m', default=100, type=int, metavar='100',
                        help='Specify the desired size in megabytes to increase by')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet output. Don\'t print the banner')
    parser.add_argument('-s', '--source', help='Source file to copy signature from')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--dictionary', type=str,
                       help='Dictionary to use for padding')
    group.add_argument('-r', '--random', action='store_true',
                       help='Use random data for padding instead of dictionary words')

    if len(sys.argv) == 1:
        # No arguments received.  Print help and exit
        print(banner)
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # ASCII art banner or GTFO
    if args.quiet:
        show_banner = False
    else:
        show_banner = True
    if show_banner:
        print(banner)

    # Make sure the specified input exists
    if not path.isfile(args.input):
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")

    # If we're not doing random generation, check to make sure the dictionary exists
    if not args.random:
        if not path.isfile(args.dictionary):
            exit("\n\nThe dictionary you specified does not exist! Please specify a valid file path.\nExiting...\n")

    input_file = args.input
    final_size = args.m

    # Split supplied file name into parts
    filename_parts = path.splitext(path.basename(input_file))
    output_filename = filename_parts[0] + '_inflated' + filename_parts[1]

    # Figure out how large our source is so we know how much to inflate it
    input_file_len = get_file_size(input_file)
    print('Original file size: ' + str(input_file_len) + ' bytes.')
    with open(input_file, 'rb') as my_file:
        with open(output_filename, 'wb') as output_file:
            output_file.write(my_file.read())

            # Get enough padding to reach target size
            # Subtract length of original file first
            # Multiply final size by 1048576 to get megabytes
            if args.random:
                padding = gen_random_bytes((final_size * 1048576) - input_file_len)
            else:
                padding = build_padding((final_size * 1048576) - input_file_len, args.dictionary)
            output_file.write(padding)
    print('New file size: ' + str(get_file_size(output_filename)) + ' bytes.')

    # Now that we have our new binary, sign it
    if args.source:
        try:
            if check_sig(args.source):
                # The signature of the source file is valid
                cert = copy_cert(args.source)
                write_cert(cert, args.source, output_filename)
            else:
                # The source binary is not signed or has an invalid signature
                exit('\n\n' + args.source + ' is not signed! Skipping signature copy.')
        except FileNotFoundError:
            exit('\n\nThe source binary you specified does not exist! Please specify a valid file path.\nExiting...\n')


if __name__ == '__main__':
    main()
