# xPipe BOF
Cobalt Strike Beacon Object File (BOF) to list active Named Pipes & return their Discretionary Access Control List (DACL) permissions.


## Credits & References
#### Cobalt Strike BOF Code Projects 
+ [trustedsec/CS-Situational-Awareness-BOF/src/SA/cacls/](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/SA/cacls/entry.c)
  + The code for the `getPipeACL()` function is derived from TrustedSecs awesome work from the CACL BOF project. 
+ [EspressoCake/HandleKatz_BOF](https://github.com/EspressoCake/HandleKatz_BOF)
  + This project taught me how to use Cobalt Strikes beacon output formatting APIs and output text to beacon with `BeaconOutput()`. This is great because it makes the text display in the CS GUI so much cleaner. The code to make this happen is pulled from this project. 
#### Malware Dev Skill References
+ [Sektor7 Malware Dev Essentials course](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
+ [OxDarkVortex Blogs](https://0xdarkvortex.dev/blogs/)
+ [Brute Ratel Blogs](https://bruteratel.com/blog/)
#### DACL Permissions Code Projects & References
+ [microsoft/Windows-classic-samples/SecPrint.c](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/security/authorization/secprint/SecPrint.c)
+ [fasterthanlime/share.c](https://gist.github.com/fasterthanlime/ea38871666bc7cc486c272650523c9e1)
+ [Microsoft Developer Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winbase/)
+ StackOverFlow - Sorry I can't find references to add. LMK and I will add them here
#### Pipe Code Projects
+ [Mark Russinovich - Sysinternals pipelist & accesscheck](https://docs.microsoft.com/en-us/sysinternals/)
  + This BOF pretty much does the same thing as `pipelist.exe`. I used `pipelist` while developing to make sure I was getting the correct listing of named pipes.
  + `accesscheck.exe -lv` will query the permissions of the named pipes like this BOF will.  
+ Decoder's Blog / Project - Windows Named Pipes & Impersonation
  + [GitHub PowerShell Project](https://github.com/decoder-it/pipeserverimpersonate)
  + [PowerShell Pipe Blog](https://decoder.cloud/2019/03/06/windows-named-pipes-impersonation/)
+ [peter-bloomfield/win32-named-pipes-example](https://github.com/peter-bloomfield/win32-named-pipes-example)
#### Cobalt Strike - How to Develop a BOF
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
