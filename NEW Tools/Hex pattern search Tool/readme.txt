// Hex_pattern_search_Tool
// Readme file
// Document has been created by Bartlomiej Duda

# Changelog #
V1.00 BDU 10.02.2019 - Initial version


# Tool Description #
This tool was designed to help users find patterns 
in hex values of game files while reverse engineering them.
It can display 4, 2 and 1 byte values converted to ASCII and integers
in multiple files. By changing input parameters user can 
modify flow of actions during script execution.
For example user is able to search for 2 byte value, treat is as
little endian in files containing name "texture" and with extension ".res" or ".img".
Data is viewed at once in one print statement to compare values in many files.

# Paramaters Description #
p_input_folder - folder for value scanning
p_mode - work mode
p_offset - offset of the value in file
p_val_length - length of the value
p_show_filenames - should filenames be visible in the final output?
p_show_paths - should file paths be visible in the final output?
p_endianess - little endian or big endian to choose
p_arr_extensions - array with valid extensions
p_show_extensions - - should extensions be visible in the final output?
p_all_extensions - should ALL extensions be visible in the final output?
p_show_file_size - - should file sizes be visible in the final output?
p_enable_calc - should calculation be executed?
p_calc_offset - calculation offset in processed file
p_operator - operator for calculate function
p_enable_regex - should filenames be matched with regex?
p_regex_filename_filter - any regex for filename

