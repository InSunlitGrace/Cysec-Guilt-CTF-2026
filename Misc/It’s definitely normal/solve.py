#!/usr/bin/env python3
"""
ZWSP Steganography Decoder - Distance Method
Usage: python3 solve.py [transcript_file]
If no file is given, defaults to 'transcript.txt'
"""

import sys

def decode(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    zwsp = '\u200b'
    
    # Find all indices of ZWSP
    indices = [i for i, c in enumerate(text) if c == zwsp]
    
    # First character: distance from start of file to first ZWSP
    flag_chars = [chr(indices[0])]
    
    # Subsequent characters: distance between consecutive ZWSPs minus 1
    for i in range(len(indices) - 1): 
        flag_chars.append(chr(indices[i+1] - indices[i] - 1))
    
    flag = ''.join(flag_chars)
    print(f"{flag}")
    return

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else 'transcript.txt'
    decode(filename)