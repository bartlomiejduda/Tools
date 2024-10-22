# MT Framework TEX Converter

## Info

This is program for converting textures from MT Framework engine.<br>
It should be able to convert from TEX to DDS and from DDS to TEX.

## Status
Work in progress....<br>
I need more TEX samples to finish the tool.

Tested games:<br>
- Dragon's Dogma: Dark Arisen (PS4) (*.TEX)

## Dependencies

* **[ReverseBox](https://github.com/bartlomiejduda/ReverseBox)**

## Usage

Converting TEX to DDS:<br>
```
python mt_framework_tex_converter.py -e input_file.tex output_file.dds
```

Converting DDS to TEX:
```
python mt_framework_tex_converter.py -i input_file.tex output_file.dds new_file.tex
```