#pragma once
#include <windows.h>
#include "error.h"
#include "debug.h"
#include <Lmcons.h>
#include <stdlib.h>

//Typedef of all the System Information
typedef struct {
	//Computer name
	wchar_t* computerName;
	//User name
	wchar_t* userName;
	//Privelege level
	BOOL admin;
	//Process Architecture
	PWSTR architecture;
} AllSI_t;

/**
* @brief  Gathers comprehensive system information including computer name, user name, privilege level, and architecture.
 *
 * This function retrieves various pieces of system information and populates
 * an AllSI_t structure with the collected data.
 *
 * @return     AllSI_t  A structure containing the gathered system information.
*/
AllSI_t GetAllSystemInformation();

/**
* @brief  Retrieves the computer name of the local machine.
 *
 * This function calls the Windows API to obtain the computer name
 * and returns it as a wide-character string.
 *
 * @return     WCHAR*  A pointer to a wide-character string containing the computer name.
*/
WCHAR* GetCompName();

/**
* @brief  Retrieves the username of the currently logged-in user.
 *
 * This function calls the Windows API to obtain the username
 * and returns it as a wide-character string.
 *
 * @return     WCHAR*  A pointer to a wide-character string containing the username.
*/
WCHAR* GetUsername();

/**
* @brief  Determines if the current user has administrative privileges.
 *
 * This function checks the user's privilege level and returns
 * TRUE if the user is an administrator, or FALSE otherwise.
 *
 * @return     BOOL  TRUE if the user has administrative privileges, FALSE otherwise.
*/
BOOL GetPriv();

/**
* @brief  Retrieves the architecture of the current process.
 *
 * This function determines the architecture (e.g., x86, x64, ARM)
 * of the running process and returns it as a wide-character string.
 *
 * @return     PWSTR  A pointer to a wide-character string containing the process architecture.
*/
PWSTR GetCompArchitecture();