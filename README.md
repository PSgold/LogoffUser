# LogoffUser
Queries and logs off a windows user account

Windows 10 Pro and above comes with the query.exe which can be used to query session Id and logoff.exe which can be used to logoff that session.
Windows 10 Home is missing these exes and i needed this functionality. So I wrote this program. kuser.exe can query session ids and logoff based on session ID.
You can also schedule a logoff within 24 hours. If you run the program from a console window with no parameters it will give you the help and list the parameters.

The program must be run with admin rights.
