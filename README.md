# logoffUser
Queries and logs off a windows user account

Windows 10 Pro and above comes with the query.exe which can be used to query session id and logoff.exe which can be used to logoff that session.
Windows 10 Home is missing these exes and i needed this functionality. So I wrote this program. kuser.exe can query session ids and logoff.
There are a few ways to use it. If using locally, you can just run it with no parameters and follow the interactive console program.
If you want to use it remotely as i am via something like powershell remoting, you need to use the parameters. You can get the parameters by running kuser.exe /?.
