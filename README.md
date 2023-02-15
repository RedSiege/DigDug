```
  ██████╗ ██╗ ██████╗     ██████╗ ██╗   ██╗ ██████╗     
  ██╔══██╗██║██╔════╝     ██╔══██╗██║   ██║██╔════╝     
  ██║  ██║██║██║  ███╗    ██║  ██║██║   ██║██║  ███╗    
  ██║  ██║██║██║   ██║    ██║  ██║██║   ██║██║   ██║    
  ██████╔╝██║╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝    
  ╚═════╝ ╚═╝ ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝
 ```
Dig Dug helps you evade some AV/EDR sandbox detection by increasing a given executable file size. Dig Dug may offer an advantage over similar tools in that it does not inflate an executable using null bytes, a repeating single character, or random data. Some AV/EDR vendors are known to test for these kinds of padding and generate an alert.


```
usage: digdug.py [-h] [-i INPUT] [-m 100] [-d DICTIONARY]

Inflate an executable with words.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file to increase size.
  -m 100                Specify the desired size in megabytes to increase by.
  -d DICTIONARY, --dictionary DICTIONARY
                        Dictionary to use for inflation.
```

## Demo
![Demo](https://github.com/hardwaterhacker/blob/main/Evasion/DigDug/images/digdug.gif)

Dig Dug takes its name from the [classic arcade game](https://en.wikipedia.org/wiki/Dig_Dug) of the same name in which the protagonist uses an air pump to defeat his enemies by inflating them until they burst.
