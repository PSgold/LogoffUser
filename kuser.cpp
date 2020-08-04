#include <iostream>
#include <iomanip>
#include <string>
#include <stdexcept>
#include <stdio.h>
#include <cstring>
#include "Windows.h"
#include "WtsApi32.h"
#include "io.h"
#include "fcntl.h"

void clearConsole( HANDLE hConsole );
void zeroWcharBuff(wchar_t* buff, unsigned short size);
void printSessions(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession);
void printHelp();
//void printWcharBuff(wchar_t* buff, unsigned short size);

int wmain(int argc, wchar_t* argv[]){
    //Do not sync iostream with C stdio
    std::wios::sync_with_stdio(false);

    //set console input and output to unicode
	_setmode(_fileno(stdout), _O_U16TEXT);
	_setmode(_fileno(stdin), _O_U16TEXT);
    
    //Get handle to STDIN and STDOUT
    HANDLE inHandle{ GetStdHandle(STD_INPUT_HANDLE) };
    HANDLE outHandle{ GetStdHandle(STD_OUTPUT_HANDLE) };

	//disable console quick edit mode so mouse click won't pause the process
	DWORD consoleMode;
	GetConsoleMode(inHandle, &consoleMode);
	SetConsoleMode(inHandle, consoleMode & (~ENABLE_QUICK_EDIT_MODE));
    
    bool qs{0};
    unsigned long sessionID{1000000};//initialize to number that will never be actual session ID
    if(argc>1){
        if (wcscmp(argv[1],L"/k")==0){
            std::wstring sessionIdWStr{argv[2]};
            try{sessionID = std::stoul(sessionIdWStr);}
            catch(std::logic_error& le){
                std::wcout<<L"\nFailed to terminate user session";
                return -1;
            }
            if(WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE,sessionID,1)!=0){
                std::wcout<<L"\nSuccessfully terminated the user session";
                return 0;                    
            }
            else {
                std::wcout<<L"\nFailed to terminate user session";
                return -1;
            }
        }
        else if(wcscmp(argv[1],L"/qs")==0)qs=1;
        else {printHelp(); return 0;}
    }
    
    std::wstring idChosen{10,L'\0'};//Will store the ID of the session to terminate
    wchar_t yesNo[10]{};//Will store final confirmation of user to terminate
    unsigned long numOfSession;
    unsigned long level{1};
    PWTS_SESSION_INFO_1W session;
    if(WTSEnumerateSessionsExW(WTS_CURRENT_SERVER_HANDLE,&level,0,&session,&numOfSession)==0){
        std::cout<<"Failed to Enumerate Sessions. Aborting!\n";return -1;
    }

    if(qs){
        std::wcout<<L'\n';
        printSessions(session,numOfSession);
        std::wcout<<L'\n';
        WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);
        return 0;
    }

    while(1){
        clearConsole(outHandle);
        printSessions(session,numOfSession);
        std::wcout<<"\nYou can type E/e to exit or->\nType the ID number of the session to terminate and press enter: ";
        std::wcout.flush();
        std::wcin.clear();
        std::wcin.getline(idChosen.data(),10);
        if(wcscmp(idChosen.data(),L"e")==0 || wcscmp(idChosen.data(),L"E")==0){
            WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);
            return 0;
        }
        try{sessionID = std::stoul(idChosen);}
        catch(std::logic_error& le){idChosen.clear();continue;}
        for(unsigned long c{0};c<numOfSession;++c){
            std::wcout<<L'\n'<<sessionID<< L" ; "<<session[c].SessionId<<L'\n';
            if(sessionID == session[c].SessionId){
                clearConsole(outHandle);
                std::wcout<<std::setw(12)<<session[c].SessionId<<
                std::setw(12)<<session[c].pUserName;
                if(session[c].State == 0)std::wcout<<std::setw(12)<<L"Connected";
                else if(session[c].State==4)std::wcout<<std::setw(12)<<L"Disconnected";
                else std::wcout<<std::setw(12)<<L"            ";
                if(session[c].pSessionName!=NULL){
                    std::wcout<<std::setw(12)<<session[c].pSessionName<<L'\n';
                }
                else std::wcout<<L"            \n";
                std::wcout<<L"\nAre you sure you want to terminate this session Y/y(anything else for no)? ";
                std::wcout.flush();std::wcin.clear();
                std::wcin.getline(yesNo,10);
                if (wcscmp(yesNo,L"Y")==0||wcscmp(yesNo,L"y")==0){
                    if(WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE,session[c].SessionId,1)!=0){
                        std::wcout<<L"\nSuccessfully terminated the user session";
                        WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);
                        return 0;                     
                    }
                    else {
                        clearConsole(outHandle);
                        std::wcout<<L"Failed to terminate user session\n\n";
                        WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);
                        return 0;                     
                    }
                }
            }
        }
        idChosen.clear();zeroWcharBuff(yesNo,10);
    }
}


void printSessions(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession){
    //print column titles
    std::wcout<<std::left<<std::setw(12)<<L"ID"<<std::setw(12)<<L"User"
    <<std::setw(12)<<L"State"<<std::setw(12)<<L"Session Type\n"
    <<"==          ====        =====       ============\n\n";

    //Print user sessions
    for(unsigned long c{0};c<numOfSession;++c){
        if(session[c].pUserName == NULL)continue;
        std::wcout<<std::setw(12)<<session[c].SessionId<<
        std::setw(12)<<session[c].pUserName;
        if(session[c].State == 0)std::wcout<<std::setw(12)<<L"Connected";
        else if(session[c].State==4)std::wcout<<std::setw(12)<<L"Disconnected";
        else std::wcout<<std::setw(12)<<L"            ";
        if(session[c].pSessionName!=NULL){
            std::wcout<<std::setw(12)<<session[c].pSessionName<<L'\n';
        }
        else std::wcout<<L"            \n";
    }
    std::wcout.flush();
}


void zeroWcharBuff(wchar_t* buff, unsigned short size){
    for (unsigned short c{0};c<size;++c)buff[c] = L'\0';
}


void printHelp(){
    wchar_t help[]{
LR"*(
Command syntax:
kuser.exe (do not use with remote console session)
kuser.exe /qs (query sessions)
kuser.exe /k [session id] (terminate session))*"
	};
	std::wcout<<help<<L'\n'<< std::endl;
}


/* void printWcharBuff(wchar_t* buff, unsigned short size){
    for(unsigned short c{0};c<size;++c){
        std::wcout<<buff[c]<<L'\n';
    }
} */

//From https://docs.microsoft.com/en-us/windows/console/clearing-the-screen
void clearConsole( HANDLE hConsole )
{
   COORD coordScreen = { 0, 0 };    // home for the cursor 
   DWORD cCharsWritten;
   CONSOLE_SCREEN_BUFFER_INFO csbi; 
   DWORD dwConSize;

// Get the number of character cells in the current buffer. 

   if( !GetConsoleScreenBufferInfo( hConsole, &csbi ))
   {
      return;
   }

   dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

   // Fill the entire screen with blanks.

   if( !FillConsoleOutputCharacter( hConsole,        // Handle to console screen buffer 
                                    (TCHAR) ' ',     // Character to write to the buffer
                                    dwConSize,       // Number of cells to write 
                                    coordScreen,     // Coordinates of first cell 
                                    &cCharsWritten ))// Receive number of characters written
   {
      return;
   }

   // Get the current text attribute.

   if( !GetConsoleScreenBufferInfo( hConsole, &csbi ))
   {
      return;
   }

   // Set the buffer's attributes accordingly.

   if( !FillConsoleOutputAttribute( hConsole,         // Handle to console screen buffer 
                                    csbi.wAttributes, // Character attributes to use
                                    dwConSize,        // Number of cells to set attribute 
                                    coordScreen,      // Coordinates of first cell 
                                    &cCharsWritten )) // Receive number of characters written
   {
      return;
   }

   // Put the cursor at its home coordinates.

   SetConsoleCursorPosition( hConsole, coordScreen );
}