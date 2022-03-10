#define _WIN32_DCOM
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <cstring>
#include "Windows.h"
#include "WtsApi32.h"
#include "io.h"
#include "fcntl.h"
#include "comdef.h"
#include "taskschd.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")

const std::wstring rootTaskFolder{L'\\'};//Task Scheduler root folder
const std::wstring customTaskFolder{L"\\Logoff"};//Task Scheduler custom folder
const std::wstring baseTaskName{L"Logoff Session "};//Base task name

void printSessions(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession);
std::wstring getSessionIdToUser(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession,int idChosen);
void printHelp();
void printNewLine(unsigned short num=1);
wchar_t* getDateTimeStrW(const std::wstring& time);
std::wstring getEndBoundaryStrW(const std::wstring& time);
int getProcessPath(wchar_t* pathBuff, unsigned short size);
short querySession();
short checkExistingTask();
short scheduleLogoffTask(const std::wstring& sessionIdWStr,const std::wstring& userToLogOff, const std::wstring& time);
short removeScheduledTask(const std::wstring& userToLogOff);

int __cdecl wmain(int argc, wchar_t* argv[]){
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
    
    unsigned long sessionID{1000000};//initialize to number that will never be actual session ID
    if(argc==2){
        if(
            wcscmp(argv[1],L"/qs")==0 || 
            wcscmp(argv[1],L"/QS")==0 || 
            wcscmp(argv[1],L"/Qs")==0 ||
            wcscmp(argv[1],L"/qS")==0
        ){querySession();return 0;}
        else if(
            wcscmp(argv[1],L"/ch")==0 || 
            wcscmp(argv[1],L"/CH")==0 || 
            wcscmp(argv[1],L"/Ch")==0 ||
            wcscmp(argv[1],L"/cH")==0
        )checkExistingTask();//Function to check for existance of task.
        else {printHelp(); return 1;}
    }
    else if(argc==3){
        if (wcscmp(argv[1],L"/k")==0 || wcscmp(argv[1],L"/K")==0){
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
        else if(
            (wcscmp(argv[1],L"/del")==0) ||
            (wcscmp(argv[1],L"/Del")==0) ||
            (wcscmp(argv[1],L"/dEl")==0) ||
            (wcscmp(argv[1],L"/deL")==0) ||
            (wcscmp(argv[1],L"/DEl")==0) ||
            (wcscmp(argv[1],L"/dEL")==0) ||
            (wcscmp(argv[1],L"/DeL")==0) ||
            (wcscmp(argv[1],L"/DEL")==0)
        ){
            const std::wstring userToLogOff{argv[2]};
            short delScheduledTaskResponse{removeScheduledTask(userToLogOff)};
            if(delScheduledTaskResponse == 1){
                printNewLine();
                std::wcout<<L"Successfully Deleted Task to Logoff "<<userToLogOff;
                printNewLine();
            }
            return 0;
        }
        else {printHelp(); return 1;}
    }
    else if(argc==5){
        if(
            (wcscmp(argv[1],L"/k")==0 && wcscmp(argv[3],L"/t")==0) || 
            (wcscmp(argv[1],L"/K")==0 && wcscmp(argv[3],L"/T")==0) ||
            (wcscmp(argv[1],L"/K")==0 && wcscmp(argv[3],L"/t")==0) ||
            (wcscmp(argv[1],L"/k")==0 && wcscmp(argv[3],L"/T")==0)
        ){
            std::wstring sessionIdWStr{argv[2]};//Stores the session ID argument to be logged off
            int idChosenInt{std::stoi(sessionIdWStr)};
            unsigned long numOfSession;
            unsigned long level{1};
            PWTS_SESSION_INFO_1W session;
            if(WTSEnumerateSessionsExW(WTS_CURRENT_SERVER_HANDLE,&level,0,&session,&numOfSession)==0){
                std::cout<<"Failed to Enumerate Sessions. Aborting!\n";return -1;
            }
            //Stores the user account name of user to be logged off
            const std::wstring userToLogOff {getSessionIdToUser(session,numOfSession,idChosenInt)};
            WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);//Free session memory
            std::wstring time{argv[4]};//Stores the requested logoff date and time
            scheduleLogoffTask(sessionIdWStr,userToLogOff,time);
            return 0;
        }
        else {printHelp(); return 1;}
    }
    else {printHelp(); return 1;}
}

std::wstring getSessionIdToUser(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession,int idChosen ){
    for(unsigned long c{0};c<numOfSession;++c){
        if(session[c].SessionId == idChosen)return session[c].pUserName;
    }
    return L"Failed to get name of user to log off";
}

void printSessions(WTS_SESSION_INFO_1W*& session,unsigned long numOfSession){
    //print column titles
    std::wcout<<std::left<<std::setw(12)<<L"ID"<<std::setw(12)<<L"User"
    <<std::setw(12)<<L"State"<<std::setw(12)<<L"Session Type";printNewLine();
    std::wcout<<L"==          ====        =====       ============";printNewLine(2);

    //Print user sessions
    for(unsigned long c{0};c<numOfSession;++c){
        if(session[c].pUserName == NULL)continue;
        std::wcout<<std::setw(12)<<session[c].SessionId<<
        std::setw(12)<<session[c].pUserName;
        if(session[c].State == 0)std::wcout<<std::setw(12)<<L"Connected";
        else if(session[c].State==4)std::wcout<<std::setw(12)<<L"Disconnected";
        else std::wcout<<std::setw(12)<<L"            ";
        if(session[c].pSessionName!=NULL){
            std::wcout<<std::setw(12)<<session[c].pSessionName;printNewLine();
        }
        else {std::wcout<<L"            ";printNewLine();}
    }
    std::wcout.flush();
}

void printHelp(){
    std::wcout.flush();
    _setmode(_fileno(stdout), _O_TEXT);

    char help[]{
R"*(
Command syntax

Query Session:
kuser.exe /qs

Terminate Session Immediately:
kuser.exe /k [session id])

Terminate Session Scheduled
kuser.exe /k [session id] /t [time]

Check Scheduled Logoff:
kuser.exe /ch

Delete Scheduled Logoff:
kuser.exe /del [username])*"
	};
	std::cout<<help<<'\n'<<'\n';
    std::cout.flush();
    
    _setmode(_fileno(stdout), _O_U16TEXT);
}

void printNewLine(unsigned short num){
    std::wcout.flush();
    std::cout.flush();
    _setmode(_fileno(stdout), _O_TEXT);
    for(unsigned short c{0};c<num;++c){
        std::cout<<'\n';
    }
    std::cout.flush();
    _setmode(_fileno(stdout), _O_U16TEXT);
}

wchar_t* getDateTimeStrW(const std::wstring& time){
    //Get system time
    std::time_t sysTime;
    std::time(&sysTime);
    std::tm cTime;//calendar time
    localtime_s(&cTime, &sysTime);//puts sysTime into tm obj which holds time as calendar time
    
    //Check if scheduled hour of day has already passed
    //If scheduled hour has passed then set date to next day
    std::wstring hr{time.substr(0,2)};
    std::wstring min{time.substr(3,2)};
    unsigned tempInt{};
    unsigned int hour {std::stoul(hr,&tempInt)};
    unsigned int minute{std::stoul(min,&tempInt)};
    if(hour<cTime.tm_hour || (hour==cTime.tm_hour&&minute<=cTime.tm_min))++(cTime.tm_mday);
    
    //places the tm obj with specific format into string buff, stringBuffO;fails if you try to put it directly into wostringstream 
    std::ostringstream stringBuffO;
    stringBuffO << std::put_time(&cTime, "%Y-%m-%d");
    const std::string dateTimeTemp{stringBuffO.str()};//Move the string in stringBuffO to standard string variable
    wchar_t* dateTimeStrW{new wchar_t[20]{}};
    unsigned short dateTimeStrWIndex{};
    for(unsigned short c{0};c<dateTimeTemp.length();++c){
        dateTimeStrW[c] = dateTimeTemp[c];
        if(c == (dateTimeTemp.length() - 1)){
            ++c;dateTimeStrW[c] = L'T';
            dateTimeStrWIndex = ++c;
        }
    }
    for(unsigned short c{0};c<time.length();++c){
        dateTimeStrW[dateTimeStrWIndex] = time[c];
        ++dateTimeStrWIndex;
        if(c == (time.length()-1)){
            dateTimeStrW[dateTimeStrWIndex] = L':';
            ++dateTimeStrWIndex;
            dateTimeStrW[dateTimeStrWIndex] = L'0';
            ++dateTimeStrWIndex;
            dateTimeStrW[dateTimeStrWIndex] = L'0';
            ++dateTimeStrWIndex;
        }
    }
    return dateTimeStrW;
}

std::wstring getEndBoundaryStrW(const std::wstring& time){
    std::wstring hr{time.substr(0,2)};
    std::wstring min{time.substr(3,2)};
    unsigned int tempInt{};
    unsigned int minute{std::stoul(min,&tempInt)};
    unsigned int hour {std::stoul(hr,&tempInt)};
    const unsigned short minToSubtract{50};
    if(minute<50)minute+=10;
    else{++hour;minute = (minute - minToSubtract);}
    hr = std::to_wstring(hour);
    min = std::to_wstring(minute);
    std::wstring colon{L':'};
    return (hr + colon + min);
}

int getProcessPath(wchar_t* pathBuff, unsigned short size){
    return GetModuleFileNameW(NULL, pathBuff, size);
}

short querySession(){
    unsigned long numOfSession;
    unsigned long level{1};
    PWTS_SESSION_INFO_1W session;
    if(WTSEnumerateSessionsExW(WTS_CURRENT_SERVER_HANDLE,&level,0,&session,&numOfSession)==0){
        std::cout<<"Failed to Enumerate Sessions. Aborting!\n";return -1;
    }
    printNewLine();
    printSessions(session,numOfSession);
    printNewLine();
    WTSFreeMemoryExW(WTSTypeSessionInfoLevel1,session,numOfSession);
    return 1;
}

short scheduleLogoffTask(const std::wstring& sessionIdWStr,const std::wstring& userToLogOff, const std::wstring& time){
    std::wstring processPath(MAX_PATH,L'\0');
    int returnValue {getProcessPath(processPath.data(),MAX_PATH)};
    if(returnValue == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER){
        printNewLine();
        std::wcout<<L"Failed to get process path";
        printNewLine();
        return -1;
    }
    //  ------------------------------------------------------
    //  Initialize COM.
    HRESULT hr {CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE)};
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeEx failed: "<<hr;printNewLine();
        return -2;
    }

        //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL
    );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeSecurity failed: "<<hr;printNewLine();
        CoUninitialize();
        return -3;
    }
    
    //  Create an instance of the Task Service. 
    ITaskService* pService {nullptr};
    hr = CoCreateInstance( 
        CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        reinterpret_cast<void**>(&pService) 
    );  
    if (FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to create an instance of ITaskService: "<<hr;
        printNewLine();
        CoUninitialize();
        return -4;
    }
        
    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),_variant_t(), _variant_t());
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"ITaskService::Connect failed: "<<hr;
        printNewLine();
        pService->Release();
        CoUninitialize();
        return -5;
    }

    //  Get the pointer to the root/custom task folder. The custom task folder will hold the
    //  new task that is registered.
    ITaskFolder* pRootFolder {nullptr};
    ITaskFolder* customFolder {nullptr};
    hr = pService->GetFolder(_bstr_t(customTaskFolder.data()),&customFolder);
    if(FAILED(hr)){
        hr = pService->GetFolder(_bstr_t(rootTaskFolder.data()),&pRootFolder);
        if(FAILED(hr)){
            printNewLine();
            std::wcout<<L"Cannot get root folder: "<<hr;
            printNewLine();
            pService->Release();
            CoUninitialize();
            return -6;
        }

        BSTR pSddl;//will hold the sddl of root ts folder and then apply it to the new subfolder
        SECURITY_INFORMATION securityInfo{};
        pRootFolder->GetSecurityDescriptor(securityInfo,&pSddl);
        hr = pRootFolder->CreateFolder(_bstr_t(customTaskFolder.data()),variant_t(pSddl),&customFolder);
        if(FAILED(hr)){
            printNewLine();
            std::wcout<<L"Cannot create custom folder: "<<hr;
            printNewLine();
            pRootFolder->Release();
            pService->Release();
            CoUninitialize();
            return -7;
        }
        pRootFolder->Release();                
    }
    
    //  If the same task exists, remove it.
    const std::wstring fullTaskName{baseTaskName+userToLogOff};
    customFolder->DeleteTask( _bstr_t(fullTaskName.data()), 0);

    //  Create the task definition object to create the task.
    ITaskDefinition* pTask {nullptr};
    hr = pService->NewTask( 0, &pTask );
    pService->Release();  // COM clean up.  Pointer is no longer used.
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to CoCreate an instance of the TaskService class: "<<hr;
        printNewLine();
        customFolder->Release();
        CoUninitialize();
        return -8;
    }

    //  Get the registration info for setting the identification.
    IRegistrationInfo* pRegInfo{nullptr};
    hr = pTask->get_RegistrationInfo( &pRegInfo );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get identification pointer: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -9;
    }
    
    std::wstring description{L"Logoff tool created by ShaiG/PSGold: Will logoff " + userToLogOff+L" at next run time"};
    hr = pRegInfo->put_Description(bstr_t(description.data()));
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to set user as description: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -10;
    }
    
    hr = pRegInfo->put_Documentation(bstr_t(userToLogOff.data()));
    pRegInfo->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to document user: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -11;
    }

    //  Create the principal for the task - these credentials
    //  are overwritten with the credentials passed to RegisterTaskDefinition
    IPrincipal* pPrincipal{nullptr};
    hr = pTask->get_Principal( &pPrincipal );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get principal pointer: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -12;
    }
    
    //  Set up principal logon type to interactive logon
    hr = pPrincipal->put_LogonType(TASK_LOGON_S4U);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put principal info: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -13;
    }

    hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    pPrincipal->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put run level to highest: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -14;
    }

    //  Create the settings for the task
    ITaskSettings* pSettings{nullptr};
    hr = pTask->get_Settings( &pSettings );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get settings pointer: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -15;
    }
    
    //  Set settings values for the task.  
    hr = pSettings->put_StartWhenAvailable(VARIANT_FALSE);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<"Cannot put setting information: "<<hr;
        printNewLine();
        customFolder->Release();
        pSettings->Release();
        pTask->Release();
        CoUninitialize();
        return -16;
    }
    hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<"Cannot put setting information: "<<hr;
        printNewLine();
        pSettings->Release();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -16;
    }
    hr = pSettings->put_DeleteExpiredTaskAfter(bstr_t(L"PT10M"));
    pSettings->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<"Cannot put setting information: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -16;
    }
    

    // Set the idle settings for the task.
    IIdleSettings *pIdleSettings{nullptr};
    hr = pSettings->get_IdleSettings( &pIdleSettings );
    pSettings->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get idle setting information: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -17;
    }

    hr = pIdleSettings->put_WaitTimeout(_bstr_t(L"PT5M"));
    pIdleSettings->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put idle setting information: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -18;
    }

    //  Get the trigger collection to insert the time trigger.
    ITriggerCollection* pTriggerCollection {nullptr};
    hr = pTask->get_Triggers( &pTriggerCollection );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get trigger collection: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -19;
    }

    //  Add the time trigger to the task.
    ITrigger* pTrigger {nullptr};    
    hr = pTriggerCollection->Create( TASK_TRIGGER_TIME, &pTrigger );     
    pTriggerCollection->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot create trigger: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -20;
    }

    ITimeTrigger* pTimeTrigger{nullptr};
    hr = pTrigger->QueryInterface(IID_ITimeTrigger, reinterpret_cast<void**>(&pTimeTrigger));
    pTrigger->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"QueryInterface call failed for ITimeTrigger: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -21;
    }

    hr = pTimeTrigger->put_Id(_bstr_t(L"Trigger1"));
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put trigger ID: "<<hr;
        printNewLine();
    }
    
    //  Set the task to start at a certain time. The time 
    //  format should be YYYY-MM-DDTHH:MM:SS(+-)(timezone).
    wchar_t* dateTimeStrW{getDateTimeStrW(time)};
    hr = pTimeTrigger->put_StartBoundary(_bstr_t(dateTimeStrW));
    delete [] dateTimeStrW;
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot add start boundary to trigger: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -22;
    }
    // Set an end boundary so it expires so we can delete task after it expires
    std::wstring endBoundaryTime{getEndBoundaryStrW(time)};
    wchar_t* endBoundaryStrW{getDateTimeStrW(endBoundaryTime)};
    hr = pTimeTrigger->put_EndBoundary(_bstr_t(endBoundaryStrW));
    pTimeTrigger->Release();
    delete [] endBoundaryStrW;
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot add end boundary to trigger: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -23;
    }

    //  Add an action to the task. This task will execute kuser.exe.     
    IActionCollection* pActionCollection{nullptr};
    hr = pTask->get_Actions( &pActionCollection );//  Get the task action collection pointer.
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get Task collection pointer: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -24;
    }

        //  Create the action, specifying that it is an executable action.
    IAction* pAction{nullptr};
    hr = pActionCollection->Create( TASK_ACTION_EXEC, &pAction );
    pActionCollection->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot create the action: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -25;
    }

    IExecAction* pExecAction{nullptr};
    //  Query interface for the executable task pointer.
    hr = pAction->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&pExecAction));
    pAction->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"QueryInterface call failed for IExecAction: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -26;
    }

    //  Set the path of the executable to kuser.exe.
    //  Set the arguments
    hr = pExecAction->put_Path(_bstr_t(processPath.data()));
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put action path: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -27;
    }
    
    std::wstring argument{(L"/k "+sessionIdWStr)};
    hr = pExecAction->put_Arguments(_bstr_t(argument.data()));
    pExecAction->Release();
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot put argument: "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -28;
    }

    //  Save the task in the custom folder.
    IRegisteredTask* pRegisteredTask{nullptr};
    hr = customFolder->RegisterTaskDefinition(
            _bstr_t(fullTaskName.data()),
            pTask,
            TASK_CREATE_OR_UPDATE, 
            _variant_t(), 
            _variant_t(), 
            TASK_LOGON_S4U,
            _variant_t(L""),
            &pRegisteredTask
    );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Error saving the Task : "<<hr;
        printNewLine();
        customFolder->Release();
        pTask->Release();
        CoUninitialize();
        return -29;
    }
    printNewLine();
    std::wcout<<L"Success! Task successfully registered. ";
    std::wcout.flush();

    //  Clean up.
    customFolder->Release();
    pTask->Release();
    pRegisteredTask->Release();
    CoUninitialize();
    return 1;
}

short checkExistingTask(){  
    //  ------------------------------------------------------
    //  Initialize COM.
    HRESULT hr {CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE)};
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeEx failed: "<<hr;printNewLine();
        return -1;
    }

        //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL
    );

    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeSecurity failed: "<<hr;printNewLine();
        CoUninitialize();
        return -2;
    }

    //  Create an instance of the Task Service. 
    ITaskService* pService {nullptr};
    hr = CoCreateInstance( 
        CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        reinterpret_cast<void**>(&pService) 
    );  
    if (FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to create an instance of ITaskService: "<<hr;
        printNewLine();
        CoUninitialize();
        return -3;
    }
        
    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),_variant_t(), _variant_t());
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"ITaskService::Connect failed: "<<hr;
        printNewLine();
        pService->Release();
        CoUninitialize();
        return -4;
    }

    //  Get the pointer to the custom task folder.
    ITaskFolder* customFolder{nullptr};
    hr = pService->GetFolder(_bstr_t(customTaskFolder.data()),&customFolder);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get custom folder: "<<hr;
        printNewLine();
        pService->Release();
        CoUninitialize();
        return -5;
    }
    
    //  -------------------------------------------------------
    //  Get the registered tasks in the folder.
    IRegisteredTaskCollection* taskCollection{nullptr};
    hr = customFolder->GetTasks(NULL, &taskCollection);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Cannot get tasks: "<<hr;
        printNewLine();
        pService->Release();
        customFolder->Release();
        CoUninitialize();
        return -6;
    }
    long taskCount{};
    taskCollection->get_Count(&taskCount);
    
    short returnCode{1};
    for(int c{1};c<=taskCount;++c){
        IRegisteredTask* task{nullptr};
        ITaskDefinition* taskDefinition{nullptr};
        IRegistrationInfo* registrationInfo{nullptr};
        BSTR definition{NULL};
        hr = taskCollection->get_Item(variant_t(c),&task);
        if(FAILED(hr)){
            printNewLine();
            std::wcout<<L"Failed to get task at index "<<c;
            printNewLine();
            SysFreeString(definition);
            returnCode = -7;
            continue;
        }
        else{
            double scheduledRunTime{};
            BSTR readableScheduledRunTime{};
            hr = task->get_NextRunTime(&scheduledRunTime);
            if(FAILED(hr)){
                std::wcout<<L"Failed to get next task runtime";
                printNewLine();
                task->Release();
                SysFreeString(readableScheduledRunTime);SysFreeString(definition);
                returnCode = -8;
                continue;
            }
            else if (scheduledRunTime == NULL){
                task->Release();
                SysFreeString(readableScheduledRunTime);SysFreeString(definition);
                continue;
            }
            else VarBstrFromDate(scheduledRunTime,NULL,LOCALE_NOUSEROVERRIDE,&readableScheduledRunTime);
            
            hr = task->get_Definition(&taskDefinition);
            if(FAILED(hr)){
                std::wcout<<L"Failed to get task definition";
                printNewLine();
                task->Release();
                SysFreeString(readableScheduledRunTime);SysFreeString(definition);
                returnCode = -9;
                continue;
            }
            else{
                hr = taskDefinition->get_RegistrationInfo(&registrationInfo);
                if(FAILED(hr)){
                    std::wcout<<L"Failed to get task registration info";
                    printNewLine();
                    task->Release();
                    taskDefinition->Release();
                    SysFreeString(readableScheduledRunTime);SysFreeString(definition);
                    returnCode = -10;
                    continue;
                }
                else{
                    hr = registrationInfo->get_Documentation(&definition);
                    if(FAILED(hr)){
                        std::wcout<<L"Failed to get task documentation";
                        printNewLine();
                        task->Release();
                        taskDefinition->Release();
                        registrationInfo->Release();
                        SysFreeString(readableScheduledRunTime);SysFreeString(definition);
                        returnCode = -11;
                        continue;
                    }
                }
            }
            taskDefinition->Release();
            registrationInfo->Release();
            task->Release();
            std::wcout<<L"Logoff of "<<definition<<L" scheduled at: "<<readableScheduledRunTime;
            if(c!=taskCount)printNewLine();
            SysFreeString(readableScheduledRunTime);SysFreeString(definition);
        }
    }
    customFolder->Release();
    pService->Release();
    taskCollection->Release();
    CoUninitialize();
    return returnCode;       
}

short removeScheduledTask(const std::wstring& userToLogOff){
    //  ------------------------------------------------------
    //  Initialize COM.
    HRESULT hr {CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE)};
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeEx failed: "<<hr;printNewLine();
        return -2;
    }

        //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL
    );
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"CoInitializeSecurity failed: "<<hr;printNewLine();
        CoUninitialize();
        return -3;
    }
    
    //  Create an instance of the Task Service. 
    ITaskService* pService {nullptr};
    hr = CoCreateInstance( 
        CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        reinterpret_cast<void**>(&pService) 
    );  
    if (FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to create an instance of ITaskService: "<<hr;
        printNewLine();
        CoUninitialize();
        return -4;
    }
        
    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),_variant_t(), _variant_t());
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"ITaskService::Connect failed: "<<hr;
        printNewLine();
        pService->Release();
        CoUninitialize();
        return -5;
    }

    //  Get the pointer to the custom task folder. The custom task folder holds the
    //  existing registered tasks
    ITaskFolder* customFolder {nullptr};
    hr = pService->GetFolder(_bstr_t(customTaskFolder.data()),&customFolder);
    if(FAILED(hr)){
        if(FAILED(hr)){
            printNewLine();
            std::wcout<<L"Cannot get custom folder: "<<hr;
            printNewLine();
            pService->Release();
            CoUninitialize();
            return -6;
        }
    }
    
    //  Delete the task
    const std::wstring fullTaskName{baseTaskName+userToLogOff};
    hr = customFolder->DeleteTask( _bstr_t(fullTaskName.data()), 0);
    if(FAILED(hr)){
        printNewLine();
        std::wcout<<L"Failed to delete the task: "<<hr;
        printNewLine();
        customFolder->Release();
        pService->Release();
        CoUninitialize();
        return -7;
    }
    
    customFolder->Release();
    pService->Release();
    CoUninitialize();
    return 1;
}