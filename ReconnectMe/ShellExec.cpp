#include "stdafx.h"
#include "ShellExec.h"


ShellExec::ShellExec()
{
#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

	// Need to link with shell32.lib
#pragma comment(lib, "shell32.lib")

	int wmain()
	{

		//-----------------------------------------
		// Declare and initialize variables
		HINSTANCE nResult;

		PCWSTR lpOperation = L"open";
		PCWSTR lpFile =
			L"shell:::{26EE0668-A00A-44D7-9371-BEB064C98683}\\3\\::{1fa9085f-25a2-489b-85d4-86326eedcd87}";

		nResult = ShellExecute(
			NULL,   // Hwnd
			lpOperation, // do not request elevation unless needed
			lpFile,
			NULL, // no parameters 
			NULL, // use current working directory 
			SW_SHOWNORMAL);

		if ((int)nResult == SE_ERR_ACCESSDENIED)
		{
			wprintf(L"ShellExecute returned access denied\n");
			wprintf(L"  Executing the ShellExecute command elevated\n");

			nResult = ShellExecute(
				NULL,
				L"runas", // Trick for requesting elevation
				lpFile,
				NULL, // no parameters 
				NULL, // use current working directory 
				SW_HIDE);
		}

		if ((int)nResult < 32) {
			wprintf(L" ShellExecute failed with error %d\n", (int)nResult);
			return 1;
		}
		else {
			wprintf(L" ShellExecute succeeded and returned value %d\n", (int)nResult);
			return 0;
		}
	}
}


ShellExec::~ShellExec()
{
}
