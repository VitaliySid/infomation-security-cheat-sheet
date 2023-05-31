### Analize memory

Format:  
`C:\volatility-2.6.standalone.exe -f [image] --profile=[profile] [plugin]`  

Image info:  
`volatility-2.6.standalone.exe -f incident.mem imageinfo`

Network connection analysis ([netscan]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem netscan`

Process analysis ([pslist], [pstree], [psscan]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem pstree`

Analysis of arguments ([cmdline], [cmdscan]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem cmdline`  

Privilege analysis ([getsids], [privs]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem getsids -p 1744,1664`  
`C:\volatility-2.6.standalone.exe -f nwe.mem privs -p 1744,1664`  

Get executable file ([procdump], [memdump]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem procdump -p 1744 -D C:\exec`  

Search for code injections ([malfind]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem malfind -p 1744,1664 -D C:\malware`  

Search for Library Injections ([dlllist], [dlldump]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem dlllist -p 1744`  
`C:\volatility-2.6.standalone.exe -f nwe.mem dlldump -p 1744 -D C:\dll`  

Process resource analysis ([handles]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem handles -p 1744 -t File --silent`  

Process memory analysis ([memdump]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem memdump -p 1744 -D C:\mem`  
`C:\strings64.exe 1744.dmp > C:\strings_1744.txt`

Search by yara rules ([yarascan]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem yarascan -Y “/(http|https)/” -p 1744`  

Data in the registry ([userassist]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem userassist`

Registry analysis ([hivelist], [printkey], [hashdump], [dumpregistry]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem dumpregistry -D C:\registry`  
`C:\volatility-2.6.standalone.exe -f nwe.mem hivelist`  
`C:\volatility-2.6.standalone.exe -f nwe.mem hashdump -y <system> -s <sam>`  

File System Analysis ([filescan], [dumpfiles]):  
`C:\volatility-2.6.standalone.exe -f nwe.mem filescan > files.txt`  
`C:\volatility-2.6.standalone.exe -f nwe.mem dumpfiles -i -r .evtx$ -D C:\evt`  

CQEVTXRecovery:  
`C:\CQEVTXRecovery.exe --in in -- out out`