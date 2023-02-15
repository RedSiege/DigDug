```
  ██████╗ ██╗ ██████╗     ██████╗ ██╗   ██╗ ██████╗     
  ██╔══██╗██║██╔════╝     ██╔══██╗██║   ██║██╔════╝     
  ██║  ██║██║██║  ███╗    ██║  ██║██║   ██║██║  ███╗    
  ██║  ██║██║██║   ██║    ██║  ██║██║   ██║██║   ██║    
  ██████╔╝██║╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝    
  ╚═════╝ ╚═╝ ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝
 ```
Dig Dug helps you evade some AV/EDR detection by increasing a given executable file size. Some engines and their sandboxes will not attempt to analyze a file if the file size is greater than some arbitrary threshold. I have not been able to find any definitive information on this threshold for various engines, discussions on offensive security Slacks and Twitter seem to agree that 100-150MB is an average threshold.

Dig Dug works by appending words from a dictionary to an executable.  This dictionary is appended repeatedly until the final desired size of the executable is reached. Dig Dug may offer an advantage over similar tools in that it does not inflate an executable using random data, which would increase entropy. Some engines, such as CrowdStrike Falcon, analyze the entropy within a binary to make a determination if the executable is trustworth to run. Other tools may append null bytes or a repeating single character. Some AV/EDR vendors are known to test for these kinds of padding and generate an alert when detected.

By default, Dig Dug uses a modified version of the [google-10000-english](https://github.com/first20hours/google-10000-english) dictionary. You can supply your own text dictionary if you prefer, for example, to have the program padded with words from another language.

```
usage: digdug.py [-h] [-i INPUT] [-m 100] [-d DICTIONARY]

Inflate an executable with words.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file to increase size.
  -m 100                Specify the desired size in megabytes to increase by.
  -q, --quiet           Quiet output. Don't print the banner                                              
  -d DICTIONARY, --dictionary DICTIONARY
                        Dictionary to use for padding 
  -r, --random          Use random data for padding instead of dictionary words

```

## Demo
![Demo](https://github.com/hardwaterhacker/DigDug/blob/main/images/digdug.gif)

Dig Dug takes its name from the [classic arcade game](https://en.wikipedia.org/wiki/Dig_Dug) of the same name in which the protagonist uses an air pump to defeat his enemies by inflating them until they burst.
