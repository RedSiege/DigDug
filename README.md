```
  ██████╗ ██╗ ██████╗     ██████╗ ██╗   ██╗ ██████╗     
  ██╔══██╗██║██╔════╝     ██╔══██╗██║   ██║██╔════╝     
  ██║  ██║██║██║  ███╗    ██║  ██║██║   ██║██║  ███╗    
  ██║  ██║██║██║   ██║    ██║  ██║██║   ██║██║   ██║    
  ██████╔╝██║╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝    
  ╚═════╝ ╚═╝ ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝
 ```
Dig Dug helps you evade some AV/EDR detections by increasing a given executable file size. Some engines will not attempt to analyze a file if the file size is greater than some arbitrary threshold. I have not been able to find any definitive information on this threshold for various engines, discussions on offensive security Slacks and Twitter seem to agree that 100-150MB is an average threshold.

Dig Dug works by appending words from a dictionary to an executable.  This dictionary is appended repeatedly until the final desired size of the executable is reached. Some AV&EDR engines, such as CrowdStrike Falcon, may measure entropy as a means of determining if an executable is trustworthy for execution. Other vendors inspect executables for signs of null byte padding. Dig Dug may offer an advantage over similar tools designed to inflate file size in that it does not inflate an executable using random data or null bytes. 

By default, Dig Dug uses a modified version of the [google-10000-english](https://github.com/first20hours/google-10000-english) dictionary. I've also supplied a dictionary, exestrings.txt, containing strings extracted from executables in Windows\System32. You can supply your own text dictionary if you prefer, for example, to have the program padded with words from another language.

Dig Dug also incorporates code from [SigThief](https://github.com/secretsquirrel/SigThief/) to copy the digital signature from a source executable to the inflated executable.

## Usage

```
usage: digdug.py [-h] [-i INPUT] [-m 100] [-d DICTIONARY]

Inflate an executable with words.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file to increase size.
  -m 100                Specify the desired size in megabytes to increase by
  -q, --quiet           Quiet output. Don't print the banner
  -s SOURCE, --source SOURCE
                        Source file to copy signature from
  -d DICTIONARY, --dictionary DICTIONARY
                        Dictionary to use for padding
  -r, --random          Use random data for padding instead of dictionary words
```

### Examples
Inflate a binary by 100 megabytes using a supplied dictionary:  
`python3 digdug.py -i calc.exe -m 100 -d dictionaries/google-10000-english-usa-gt5.txt`

Inflate a binary by 100 megabytes using random data:  
`python3 digdug.py -i calc.exe -m 100 -r`

Inflate a binary by 100 megabytes and steal a signature from consent.exe:  
`python3 digdug.py -i calc.exe -m 100 -d dictionaries/google-10000-english-usa-gt5.txt -s consent.exe`

## Demo
<img src="https://github.com/hardwaterhacker/DigDug/blob/main/images/digdug.gif" width="65%" alt="Demonstration of DigDug">

## Credits
- Dig Dug was inspired by [Mangle](https://github.com/optiv/Mangle).  
- Dig Dug uses portions of [SigThief](https://github.com/secretsquirrel/SigThief/) to copy the digital signature of a file.

## Misc.
Dig Dug takes its name from the [classic arcade game](https://en.wikipedia.org/wiki/Dig_Dug) of the same name in which the protagonist uses an air pump to defeat his enemies by inflating them until they burst.
