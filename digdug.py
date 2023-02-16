#!/usr/bin/env python3
import argparse
import os
import random
import string
import sys


def gen_random_bytes(desired_size):
    # Generates a random key of desired_size length
    return bytes(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase)
                         for _ in range(desired_size)), 'ascii')


def build_padding(desired_size, dictionary_file):
    # read in words dictionary
    sizeof_dictionary_file = os.stat(dictionary_file).st_size

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
    my_file_stats = os.stat(my_file)
    my_file_len = my_file_stats.st_size
    return my_file_len


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
                        help="Input file to increase size.")
    parser.add_argument('-m', default=100, type=int, metavar='100',
                        help='Specify the desired size in megabytes to increase by')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet output. Don\'t print the banner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--dictionary', default='google-10000-english-usa-gt5.txt', type=str,
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
    if not os.path.isfile(args.input):
        exit("\n\nThe input file you specified does not exist! Please specify a valid file path.\nExiting...\n")

    # If we're not doing random generation, check to make sure the dictionary exists
    if not args.random:    
        if not os.path.isfile(args.dictionary):
            exit("\n\nThe dictionary you specified does not exist! Please specify a valid file path.\nExiting...\n")
        
    input_file = args.input
    final_size = args.m

    filename_parts = os.path.splitext(os.path.basename(input_file))
    output_filename = filename_parts[0] + '_inflated' + filename_parts[1]

    input_file_len = get_file_size(input_file)

    print('Original file size: ' + str(input_file_len) + ' bytes.')
    with open(input_file, 'rb') as my_file:
        with open(output_filename, 'wb') as output_file:
            output_file.write(my_file.read())
            
            # Get enough padding to reach target size
            # Subtract length of original file first
            if args.random:
                padding = gen_random_bytes((final_size * 1048576) - input_file_len)
            else:
                padding = build_padding((final_size * 1048576) - input_file_len, args.dictionary)
            output_file.write(padding)

    print('New file size: ' + str(get_file_size(output_filename)) + ' bytes.')

if __name__ == '__main__':
    main()

