@echo off
cls
echo Please enter the image path (e.g. C:\John-PC.raw, without quotation marks)
set /p FILE=: 
echo What Windows was it taken from (e.g. WinXPSP3x86, VistaSP2x86, Win7SP1x86) ?
set /P PROFILE=: 

if exist "%FILE%" goto RUN
echo The file couldn't be found!
goto END


:RUN

::
:: Values to be adjusted by the user
::
set PATH=%PATH%;.\unxtools
set OUTPUT_FOLDER=output
set MODULE_NAME=truecrypt.sys

set PWD_OUTPUT=%output_folder%\passwords.txt
set STR_OUTPUT=%output_folder%\passwords_vol.txt
set MDL_OUTPUT=%output_folder%\modules.txt

::
:: The parameter 'non-decimal-data' and adding zero makes it convert hex to decimal
::
set AWK_MIN=gawk --non-decimal-data "{ print ($3)+0; }"
set AWK_MAX=gawk --non-decimal-data "{ print ($3+$4); }"

::
:: Creating the output folder
::
mkdir %output_folder% 2> NUL

::
:: Extracting data
::
ECHO.
ECHO (1/3) Running Cryptoscan.
python volatility cryptoscan -f "%file%" > "%cd%\%pwd_output%"
ECHO.
ECHO (2/3) Associating strings with the processes they belong to.
volatility.exe strings --profile=%profile% -f "%file%" -s "%pwd_output%" > "%str_output%"
ECHO.
ECHO (3/3) Eliminating strings that don't belong to the TrueCrypt's driver.
volatility.exe modules --profile=%profile% -f "%file%" > "%mdl_output%"
ECHO.
ECHO Finished extracting data.
pause

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
set HEX2DEC_SECOND_VALUE=(^$2)+0
set AWK_LCONDITION=%hex2dec_second_value% ^>= \"%min_offset%\"
set AWK_RCONDITION=%hex2dec_second_value% ^<= \"%max_offset%\"

::
:: Printing found passwords
::
cls
ECHO Found passwords:
type "%str_output%" | grep %grep_param% | sed %sed_param% | gawk --non-decimal-data "{ if(%awk_lcondition% && %awk_rcondition%) print $3 }"

:END
pause