// ReconnectMe.cpp : Defines the entry point for the console application.
//

#ifndef UNICODE
#define UNICODE
#endif

#include "stdafx.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <Wlanapi.h>
#include <chrono>
#include <thread>
#include <shellapi.h>
#include <stdio.h>
#include <objbase.h>
#include <wtypes.h>
#include <stdlib.h>
#include <Wlantypes.h>

//for exec
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

//for splitting String
#include <sstream>

//for checking if Inernetconnection is available
#include <wininet.h>

// Need to link with shell32.lib
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

//Executes a windows command 
std::string exec(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) throw std::runtime_error("_popen() failed!");
	while (!feof(pipe.get())) {
		if (fgets(buffer.data(), 128, pipe.get()) != NULL)
			result += buffer.data();
	}
	return result;
}


//Parse String to wideString
std::wstring get_utf16(const std::string &str, int codepage)
{
	if (str.empty()) return std::wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	std::wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

int main() {

	using namespace std;
	using namespace std::this_thread;     // sleep_for, sleep_until
	using namespace std::chrono_literals; //using seconds()



	//Variable Declaration
	HINSTANCE nResult;
	HANDLE hClient = NULL;

	PWLAN_CONNECTION_PARAMETERS pConnectionParameters = NULL;
	WLAN_CONNECTION_PARAMETERS connectionParameters;

	DWORD pdwNegotiatedVersion = NULL;
	DWORD dwMaxClient = 2;
	DWORD dwCurVersion = 0;
	DWORD dwResult = NULL;
	DWORD dwRetVal = 0;
	LPCWSTR strProfileName = NULL;
	DOT11_SSID dot11Ssid = { 0 };
	DWORD dwPrevNotif = 0;



	/* variables used for WlanEnumInterfaces  */
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;

	/* variables used for WlanGetAvailableNetworkList */
	PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
	PWLAN_AVAILABLE_NETWORK pBssEntry = NULL;

	/* variables used for GetProfileList */
	PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
	PWLAN_PROFILE_INFO pProfile = NULL;
	LPCWSTR pProfileName = NULL;
	LPWSTR pProfileXml = NULL;

	// variables used for GetProfile
	DWORD dwFlags = 0;
	DWORD dwGrantedAccess = 0;

	WCHAR GuidString[40] = { 0 };
	int iRet = 0;
	unsigned int i, j, k;




	







	while (true) {

		//Run cmd and return the current SSID
		string result = exec("NETSH WLAN SHOW INTERFACE | findstr /r \"^....SSID\"");

		std::string s(result);
		std::istringstream iss(s);

		//Gets the SSID (not very sexy way)
		for (int i = 0; i < 3;i++)
		{
			std::string sub;
			iss >> sub;
			result = sub;
		};
		std::wstring abc = get_utf16(result, CP_UTF8);
		pProfileName = abc.c_str();




		//Set some connection parameters
		char *wStrC = new char[256];

		dot11Ssid.uSSIDLength = lstrlen(pProfileName);

		size_t wLen = 0;
		errno_t err = 0;

		wcstombs_s(&wLen, wStrC, 256, pProfileName, _TRUNCATE);
		memcpy(&dot11Ssid.ucSSID, wStrC, wLen);
		if (wStrC)
		{
			free(wStrC);
		}



		connectionParameters.wlanConnectionMode = wlan_connection_mode_profile;
		connectionParameters.strProfile = pProfileName;
		connectionParameters.pDot11Ssid = &dot11Ssid;
		connectionParameters.pDesiredBssidList = NULL;
		connectionParameters.dot11BssType = dot11_BSS_type_infrastructure;
		connectionParameters.dwFlags = 0;

		pConnectionParameters = &connectionParameters;

		if (InternetCheckConnection(L"http://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0))
		{
			printf("connected to internet\n");

		}
		else {
			dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);

			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
				return 1;
				// You can use FormatMessage here to find out why the function failed
			}
			else {
				printf("WlanOpenHandle is Working\n ");
			}





			dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);

			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanEnumInterfaces failed with error: %u\n", dwResult);
				// FormatMessage can be used to find out why the function failed
				return 1;
			}
			else {
				printf("WlanEnumInterfaces is Working\n ");
				wprintf(L"Num Entries: %lu\n", pIfList->dwNumberOfItems);
				wprintf(L"Current Index: %lu\n", pIfList->dwIndex);
				for (i = 0; i < (int)pIfList->dwNumberOfItems; i++) {
					pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
					wprintf(L"  Interface Index[%d]:\t %lu\n", i, i);
					//save the GUID

					iRet = StringFromGUID2(pIfInfo->InterfaceGuid, (LPOLESTR)&GuidString, 39);
					// For c rather than C++ source code, the above line needs to be
					// iRet = StringFromGUID2(&pIfInfo->InterfaceGuid, (LPOLESTR) &GuidString, 39); 
					if (iRet == 0)
						wprintf(L"StringFromGUID2 failed\n");
					else {
						wprintf(L"  InterfaceGUID[%d]: %ws\n", i, GuidString);

					}
					wprintf(L"  Interface Description[%d]: %ws", i, pIfInfo->strInterfaceDescription);
					wprintf(L"\n");
					wprintf(L"  Interface State[%d]:\t ", i);
					switch (pIfInfo->isState) {
					case wlan_interface_state_not_ready:
						wprintf(L"Not ready\n");
						break;
					case wlan_interface_state_connected:
						wprintf(L"Connected\n");
						break;
					case wlan_interface_state_ad_hoc_network_formed:
						wprintf(L"First node in a ad hoc network\n");
						break;
					case wlan_interface_state_disconnecting:
						wprintf(L"Disconnecting\n");
						break;
					case wlan_interface_state_disconnected:
						wprintf(L"Not connected\n");
						break;
					case wlan_interface_state_associating:
						wprintf(L"Attempting to associate with a network\n");
						break;
					case wlan_interface_state_discovering:
						wprintf(L"Auto configuration is discovering settings for the network\n");
						break;
					case wlan_interface_state_authenticating:
						wprintf(L"In process of authenticating\n");
						break;
					default:
						wprintf(L"Unknown state %ld\n", pIfInfo->isState);
						break;
					}
					wprintf(L"\n");
				}
			}

			//Print the Profile for SSID
			wprintf(L"Information for profile: %ws\n\n", pProfileName);

			dwResult = WlanGetProfile(hClient, &pIfInfo->InterfaceGuid, pProfileName, NULL, &pProfileXml, &dwFlags, &dwGrantedAccess);
			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanGetProfile failed with error: %u\n",
					dwResult);
				// You can use FormatMessage to find out why the function failed
				switch (dwResult) {
				case ERROR_ACCESS_DENIED:
					printf("ERROR_ACCESS_DENIED\n The caller does not have sufficient permissions.This error is returned if the pstrProfileXml parameter specifies an all - user profile, but the caller does not have read access on the profile.\n");
					break;
				case ERROR_INVALID_HANDLE:
					printf("ERROR_INVALID_HANDLE\n A handle is invalid.This error is returned if the handle specified in the hClientHandle parameter was not found in the handle table.\n");
					break;
				case ERROR_INVALID_PARAMETER:
					printf("ERROR_INVALID_PARAMETER\n A parameter is incorrect.This error is returned if any of the following conditions occur :hClientHandle is NULL.\n\
				pInterfaceGuid is NULL.\n\
				pstrProfileXml is NULL.\n\
				pReserved is not NULL.\n");
					break;
				case ERROR_NOT_ENOUGH_MEMORY:
					printf("ERROR_NOT_ENOUGH_MEMORY\n Not enough storage is available to process this command.This error is returned if the system was unable to allocate memory for the profile.\n");
					break;
				case ERROR_NOT_FOUND:
					printf("ERROR_NOT_FOUND\n The profile specified by strProfileName was not found.\n Other\nVarious RPC and other error codes.Use FormatMessage to obtain the message string for the returned error.\n");
					break;
				}

			}
			else {
				wprintf(L"  Profile Name:  %ws\n", pProfileName);

				wprintf(L"  Profile XML string:\n");
				wprintf(L"%ws\n\n", pProfileXml);

				wprintf(L"  dwFlags:\t    0x%x", dwFlags);
				if (dwFlags & WLAN_PROFILE_GET_PLAINTEXT_KEY)
					wprintf(L"   Get Plain Text Key");
				if (dwFlags & WLAN_PROFILE_GROUP_POLICY)
					wprintf(L"  Group Policy");
				if (dwFlags & WLAN_PROFILE_USER)
					wprintf(L"  Per User Profile");
				wprintf(L"\n");

				wprintf(L"  dwGrantedAccess:  0x%x", dwGrantedAccess);
				if (dwGrantedAccess & WLAN_READ_ACCESS)
					wprintf(L"  Read access");
				if (dwGrantedAccess & WLAN_EXECUTE_ACCESS)
					wprintf(L"  Execute access");
				if (dwGrantedAccess & WLAN_WRITE_ACCESS)
					wprintf(L"  Write access");
				wprintf(L"\n");

				wprintf(L"\n");
			}


			//Show All Profiles
			dwResult = WlanGetProfileList(hClient,
				&pIfInfo->InterfaceGuid,
				NULL,
				&pProfileList);

			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanGetProfileList failed with error: %u\n",
					dwResult);
				dwRetVal = 1;
				// You can use FormatMessage to find out why the function failed
			}
			else {
				wprintf(L"WLAN_PROFILE_INFO_LIST for this interface\n");

				wprintf(L"  Num Entries: %lu\n\n", pProfileList->dwNumberOfItems);

				for (j = 0; j < pProfileList->dwNumberOfItems; j++) {
					pProfile =
						(WLAN_PROFILE_INFO *)& pProfileList->ProfileInfo[j];

					wprintf(L"  Profile Name[%u]:  %ws\n", j, pProfile->strProfileName);

					wprintf(L"  Flags[%u]:\t    0x%x", j, pProfile->dwFlags);
					if (pProfile->dwFlags & WLAN_PROFILE_GROUP_POLICY)
						wprintf(L"   Group Policy");
					if (pProfile->dwFlags & WLAN_PROFILE_USER)
						wprintf(L"   Per User Profile");
					wprintf(L"\n");

					wprintf(L"\n");
				}
			}
			for (j = 0; j < pProfileList->dwNumberOfItems; j++) {
				pProfile =
					(WLAN_PROFILE_INFO *)& pProfileList->ProfileInfo[j];
			}


			dwResult = WlanGetAvailableNetworkList(hClient, &pIfInfo->InterfaceGuid, 0, NULL, &pBssList);

			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanGetAvailableNetworkList failed with error: %u\n",
					dwResult);
				dwRetVal = 1;
				// You can use FormatMessage to find out why the function failed
			}
			else {
				wprintf(L"WLAN_AVAILABLE_NETWORK_LIST for this interface\n");

				wprintf(L"  Num Entries: %lu\n\n", pBssList->dwNumberOfItems);

				for (j = 0; j < pBssList->dwNumberOfItems; j++) {
					pBssEntry =
						(WLAN_AVAILABLE_NETWORK *)& pBssList->Network[j];

					wprintf(L"  Profile Name[%u]:  %ws\n", j, pBssEntry->strProfileName);

					wprintf(L"  SSID[%u]:\t\t ", j);
					if (pBssEntry->dot11Ssid.uSSIDLength == 0)
						wprintf(L"\n");
					else {
						for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
							wprintf(L"%c", (int)pBssEntry->dot11Ssid.ucSSID[k]);
						}
						wprintf(L"\n");
					}

					wprintf(L"  BSS Network type[%u]:\t ", j);
					switch (pBssEntry->dot11BssType) {
					case dot11_BSS_type_infrastructure:
						wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
						break;
					case dot11_BSS_type_independent:
						wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
						break;
					default:
						wprintf(L"Other (%lu)\n", pBssEntry->dot11BssType);
						break;
					}

					wprintf(L"  Number of BSSIDs[%u]:\t %u\n", j, pBssEntry->uNumberOfBssids);

					wprintf(L"  Connectable[%u]:\t ", j);
					if (pBssEntry->bNetworkConnectable)
						wprintf(L"Yes\n");
					else
						wprintf(L"No\n");

					wprintf(L"  Signal Quality[%u]:\t %u\n", j, pBssEntry->wlanSignalQuality);

					wprintf(L"  Security Enabled[%u]:\t ", j);
					if (pBssEntry->bSecurityEnabled)
						wprintf(L"Yes\n");
					else
						wprintf(L"No\n");

					wprintf(L"  Default AuthAlgorithm[%u]: ", j);
					switch (pBssEntry->dot11DefaultAuthAlgorithm) {
					case DOT11_AUTH_ALGO_80211_OPEN:
						wprintf(L"802.11 Open (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_80211_SHARED_KEY:
						wprintf(L"802.11 Shared (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_WPA:
						wprintf(L"WPA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_WPA_PSK:
						wprintf(L"WPA-PSK (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_WPA_NONE:
						wprintf(L"WPA-None (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_RSNA:
						wprintf(L"RSNA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					case DOT11_AUTH_ALGO_RSNA_PSK:
						wprintf(L"RSNA with PSK(%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					default:
						wprintf(L"Other (%lu)\n", pBssEntry->dot11DefaultAuthAlgorithm);
						break;
					}

					wprintf(L"  Default CipherAlgorithm[%u]: ", j);
					switch (pBssEntry->dot11DefaultCipherAlgorithm) {
					case DOT11_CIPHER_ALGO_NONE:
						wprintf(L"None (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					case DOT11_CIPHER_ALGO_WEP40:
						wprintf(L"WEP-40 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					case DOT11_CIPHER_ALGO_TKIP:
						wprintf(L"TKIP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					case DOT11_CIPHER_ALGO_CCMP:
						wprintf(L"CCMP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					case DOT11_CIPHER_ALGO_WEP104:
						wprintf(L"WEP-104 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					case DOT11_CIPHER_ALGO_WEP:
						wprintf(L"WEP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					default:
						wprintf(L"Other (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
						break;
					}

					wprintf(L"\n");

				}
			}








			//	Faild to connect to Google. Try Disconnect and Connect again		
			printf("Try to DISCONNECT WLAN\n ");
			dwResult = WlanDisconnect(hClient, &pIfInfo->InterfaceGuid, NULL);
			if (dwResult != ERROR_SUCCESS) {
				switch (dwResult)
				{
				case ERROR_INVALID_PARAMETER:
					printf("ERROR_INVALID_PARAMETER\n hClientHandle is NULL or invalid, pInterfaceGuid is NULL, or pReserved is not NULL.hClientHandle is NULL or invalid, pInterfaceGuid is NULL, or pReserved is not NULL.\n");
					break;
				case ERROR_INVALID_HANDLE:
					printf("ERROR_INVALID_HANDLE\n The handle hClientHandle was not found in the handle table.\n");
					break;

				case ERROR_NOT_ENOUGH_MEMORY:
					printf("ERROR_NOT_ENOUGH_MEMORY\n Failed to allocate memory for the query results\n");
					break;

				case ERROR_ACCESS_DENIED:
					printf("ERROR_ACCESS_DENIED\n The caller does not have sufficient permissions.\n ");
					break;
				}
			}
			else { printf("WLAN is DISCONNECTED\n "); }


			printf("TRY To Connect again\n ");

			dwResult = WlanConnect(hClient, &pIfInfo->InterfaceGuid, &connectionParameters, NULL);
			if (dwResult != ERROR_SUCCESS) {
				switch (dwResult)
				{
				case ERROR_INVALID_HANDLE:
					printf("INVALID HANDLE\n");
					break;
				case ERROR_ACCESS_DENIED:
					printf("NO PERMISSION TO CONNECT\n");
					break;
				case ERROR_INVALID_PARAMETER:
					printf("INVALID PARAMETERS\n");
					break;
				}
			}
			else {
				printf("Reconnected, have fun! \n ");
			}


			//	}
			//	catch (...) {}

			//}





			//cleaning
			if (pIfList != NULL) {
				WlanFreeMemory(pIfList);
				pIfList = NULL;
			}

			if (pProfileList != NULL) {
				WlanFreeMemory(pProfileList);
				pProfileList = NULL;
			}

			if (pProfileXml != NULL) {
				WlanFreeMemory(pProfileXml);
				pProfileXml = NULL;
			}
		}
		//sleep until next check
		sleep_for(15s);

	}

	return 0; //EOP
}

