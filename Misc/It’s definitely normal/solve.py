#!/usr/bin/env python3
import sys

def decode(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    zwsp = '\u200b'
    
    indices = [i for i, c in enumerate(text) if c == zwsp]
    flag_chars = [chr(indices[0])]
    
    for i in range(len(indices) - 1): 
        flag_chars.append(chr(indices[i+1] - indices[i] - 1))
    
    flag = ''.join(flag_chars)
    print(f"{flag}")
    return

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else 'transcript.txt'
    decode(filename)