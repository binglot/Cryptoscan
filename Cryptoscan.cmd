@echo off
cls
set /p FILE=Please enter the image's path: 

::
:: Values to be adjusted by the user
::
set PATH=%PATH%;.\gnuwin32
set OUTPUT_FOLDER=output
set MODULE_NAME=truecrypt.sys

set PWD_OUTPUT=%output_folder%\passwords.txt
set STR_OUTPUT=%output_folder%\passwords_vol.txt
set MDL_OUTPUT=%output_folder%\modules.txt

::
:: The parameter 'non-decimal-data' and adding zero makes it convert hex to decimal
::
set AWK_MIN=awk --non-decimal-data "{ print ($2)+0; }"
set AWK_MAX=awk --non-decimal-data "{ print ($2+$3); }"

::
:: Creating the output folder
::
mkdir %output_folder% 2> NUL

::
:: Extracting data
::
::	There's a bug within the framework so that if volatility is run from different
:: 	directory then its own then it doesn't find external plugins, hence the dirty trick.
::
python volatility cryptoscan -f "%file%" > "%cd%\%pwd_output%"
python volatility strings -f "%file%" -s "%pwd_output%" > "%str_output%"
python volatility modules -f "%file%" > "%mdl_output%"

::
:: Calculating a memory range of the module.
::
for /f "tokens=*" %%a in ('type "%mdl_output%" ^| grep "%module_name%" ^| %awk_min%') do set MIN_OFFSET=%%a
for /f "tokens=*" %%a in ('type "%mdl_output%" ^| grep "%module_name%" ^| %awk_max%') do set MAX_OFFSET=%%a

::
:: Variables extracted for the sake of readability (does it really make a difference?!)
::
set GREP_PARAM=kernel
set SED_PARAM="s/\[kernel://g"
set SECONDVALUE=(\"0x\"^$2)+0
set AWK_CONDITION=%secondvalue% ^>^= \"%min_offset%\" ^&^& %secondvalue% ^<^= \"%max_offset%\"

cls
type "%str_output%" | grep %grep_param% | sed %sed_param% | awk --non-decimal-data "{ if(%awk_condition%) print \"Found password:\",$4 }" | sort
pause