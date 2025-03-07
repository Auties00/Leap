jextract --library user32 -t it.auties.leap.socket.implementation.win --output ".\..\..\src\main\java" WindowsSockets.h --header-class-name WindowsSockets ^
--include-function WSAStartup ^
--include-function WSASocketA ^
--include-function WSAConnect ^
--include-function WSASend ^
--include-function WSARecv ^
--include-constant AF_INET ^
--include-constant SOCK_STREAM ^
--include-constant IPPROTO_TCP ^
--include-constant WSA_FLAG_OVERLAPPED ^
--include-constant INVALID_SOCKET ^
--include-struct _OVERLAPPED ^
--include-struct _WSABUF ^
--include-struct in_addr ^
--include-struct OVERLAPPED ^
--include-struct sockaddr_in ^
--include-struct SOCKADDR ^
--include-function WSAGetLastError ^
--include-constant WSA_IO_PENDING ^
--include-function closesocket ^
--include-function WSAWaitForMultipleEvents ^
--include-constant INFINITE ^
--include-function CreateIoCompletionPort ^
--include-function GetQueuedCompletionStatus ^
--include-function GetQueuedCompletionStatusEx ^
--include-typedef HANDLE ^
--include-struct _OVERLAPPED_ENTRY ^
--include-typedef OVERLAPPED_ENTRY ^
--include-typedef LPOVERLAPPED_ENTRY ^
--include-function GetOverlappedResult ^
--include-function GetLastError ^
--include-typedef SOCKET ^
--include-function CloseHandle ^
--include-function WSAIoctl ^
--include-constant SIO_GET_EXTENSION_FUNCTION_POINTER ^
--include-struct _GUID ^
--include-typedef LPFN_CONNECTEX ^
--include-typedef DWORD ^
--include-typedef LPDWORD ^
--include-typedef WORD ^
--include-typedef BOOL ^
--include-typedef PVOID ^
--include-typedef LPOVERLAPPED  ^
--include-function inet_addr ^
--include-struct WSAData ^
--include-typedef ULONG ^
--include-constant INADDR_NONE ^
--include-function WSACleanup ^
--include-function socket ^
--include-constant INADDR_ANY ^
--include-function bind ^
--include-constant SOCKET_ERROR ^
--include-function setsockopt ^
--include-constant SOL_SOCKET ^
--include-constant SO_UPDATE_CONNECT_CONTEXT ^
--include-constant SO_KEEPALIVE