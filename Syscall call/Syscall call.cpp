// Syscall call.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include "Ntdll.hpp"
#include "SyscallGet.hpp"
inline BOOL NtCloseAntiDeb() {
	__try{
		NtApiWork::SyscallNtClose((HANDLE)0x1337);
	
	}	
		__except (1) {
		return true;
	}
	return false;
}



int main()
{

	//syscallWork::printSyscall();
    DWORD ntClose = syscallWork::GetSyscallByName("7d86a3c287cc4e67310a555a92c8a3ab46b3b37b3311138843df89ad24b5da45");
	DWORD NtTermProc = syscallWork::GetSyscallByName("e95a46a765f3fc807e10affbe61db8cb58b480c08eb1a01ecf1fd1d3fedb48c7");
	if (ntClose  >0 && NtTermProc > 0) {

		std::cout << "Syscall NtClose/ZwClose ->\t" << std::hex << ntClose << '\n';
		std::cout << "Syscall NtTerminateProcess ->\t" << std::hex << NtTermProc << '\n';

		syscallWork::SetCallNumber(ntClose);
		std::cout << "Anti-Debug ->\t" << NtCloseAntiDeb() << '\n';


	}
	else {
		std::cout << "Shylla hide detect or bad Anti-Virus!!!" << '\n';
	}
	std::cin.get();
	system("pause");
	syscallWork::SetCallNumber(NtTermProc);
	NtApiWork::SyscallTerminateProc((HANDLE)-1, 0x1337);
}
