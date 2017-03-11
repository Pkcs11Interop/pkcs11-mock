/*
 *  Copyright 2011-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "pkcs11-mock.h"


CK_BBOOL pkcs11_mock_initialized = CK_FALSE;
CK_BBOOL pkcs11_mock_session_opened = CK_FALSE;
CK_ULONG pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_MOCK_CK_OPERATION pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
CK_OBJECT_HANDLE pkcs11_mock_find_result = CKR_OBJECT_HANDLE_INVALID;


CK_FUNCTION_LIST pkcs11_mock_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (CK_TRUE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	IGNORE(pInitArgs);

	pkcs11_mock_initialized = CK_TRUE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);

	pkcs11_mock_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = 0x02;
	pInfo->cryptokiVersion.minor = 0x14;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MINOR;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_mock_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(tokenPresent);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlotList)
	{
		*pulCount = 1;
	}
	else
	{
		if (0 == *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_MOCK_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_MOCK_CK_TOKEN_INFO_LABEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_MOCK_CK_TOKEN_INFO_MODEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MODEL));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER, strlen(PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER));
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = (CK_TRUE == pkcs11_mock_session_opened) ? 1 : 0;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_mock_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_mock_session_state) || (CKS_RO_USER_FUNCTIONS != pkcs11_mock_session_state))) ? 1 : 0;
	pInfo->ulMaxPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pMechanismList)
	{
		*pulCount = 9;
	}
	else
	{
		if (9 > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pMechanismList[1] = CKM_RSA_PKCS;
		pMechanismList[2] = CKM_SHA1_RSA_PKCS;
		pMechanismList[3] = CKM_RSA_PKCS_OAEP;
		pMechanismList[4] = CKM_DES3_CBC;
		pMechanismList[5] = CKM_DES3_KEY_GEN;
		pMechanismList[6] = CKM_SHA_1;
		pMechanismList[7] = CKM_XOR_BASE_AND_DATA;
		pMechanismList[8] = CKM_AES_CBC;

		*pulCount = 9;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	switch (type)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;

		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP;
			break;

		case CKM_SHA1_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;

		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_CBC:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_KEY_GEN:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_GENERATE;
			break;

		case CKM_SHA_1:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;

		case CKM_XOR_BASE_AND_DATA:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_DERIVE;
			break;

		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pLabel)
		return CKR_ARGUMENTS_BAD;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_EXISTS;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (CKS_RW_SO_FUNCTIONS != pkcs11_mock_session_state)
		return CKR_USER_NOT_LOGGED_IN;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKS_RO_PUBLIC_SESSION == pkcs11_mock_session_state) || (CKS_RO_USER_FUNCTIONS == pkcs11_mock_session_state))
		return CKR_SESSION_READ_ONLY;

	if (NULL == pOldPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulOldLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pNewPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulNewLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_COUNT;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	IGNORE(pApplication);

	IGNORE(Notify);

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;

	pkcs11_mock_session_opened = CK_TRUE;
	pkcs11_mock_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	*phSession = PKCS11_MOCK_CK_SESSION_ID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = PKCS11_MOCK_CK_SLOT_ID;
	pInfo->state = pkcs11_mock_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_mock_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_mock_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pOperationState)
	{
		*pulOperationStateLen = 256;
	}
	else
	{
		if (256 > *pulOperationStateLen)
			return CKR_BUFFER_TOO_SMALL;

		memset(pOperationState, 1, 256);
		*pulOperationStateLen = 256;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pOperationState)
		return CKR_ARGUMENTS_BAD;

	if (256 != ulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	IGNORE(hEncryptionKey);

	IGNORE(hAuthenticationKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKU_SO != userType) && (CKU_USER != userType))
		return CKR_USER_TYPE_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			if (CKU_SO == userType)
				rv = CKR_SESSION_READ_ONLY_EXISTS;
			else
				pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;

			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ANOTHER_ALREADY_LOGGED_IN : CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:

			pkcs11_mock_session_state = (CKU_SO == userType) ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ALREADY_LOGGED_IN : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((pkcs11_mock_session_state == CKS_RO_PUBLIC_SESSION) || (pkcs11_mock_session_state == CKS_RW_PUBLIC_SESSION))
		return CKR_USER_NOT_LOGGED_IN;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phObject)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phNewObject)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 >= ulCount))
	{
		for (i = 0; i < ulCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phNewObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pulSize)
		return CKR_ARGUMENTS_BAD;

	*pulSize = PKCS11_MOCK_CK_OBJECT_SIZE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (CKA_LABEL == pTemplate[i].type)
		{
			if (NULL != pTemplate[i].pValue)
			{
				if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL))
					return CKR_BUFFER_TOO_SMALL;
				else
					memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_LABEL, strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL));
			}

			pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL);
		}
		else if (CKA_VALUE == pTemplate[i].type)
		{
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY == hObject)
			{
				pTemplate[i].ulValueLen = (CK_ULONG) -1;
			}
			else
			{
				if (NULL != pTemplate[i].pValue)
				{
					if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE))
						return CKR_BUFFER_TOO_SMALL;
					else
						memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_VALUE, strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE));
				}

				pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE);
			}
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if ((CKA_LABEL == pTemplate[i].type) || (CKA_VALUE == pTemplate[i].type))
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;
	CK_ULONG_PTR cka_class_value = NULL;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	IGNORE(ulCount);

	pkcs11_mock_find_result = CK_INVALID_HANDLE;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (CKA_CLASS == pTemplate[i].type)
		{
			if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			cka_class_value = (CK_ULONG_PTR) pTemplate[i].pValue;

			switch (*cka_class_value)
			{
				case CKO_DATA:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;
					break;
				case CKO_SECRET_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;
					break;
				case CKO_PUBLIC_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
					break;
				case CKO_PRIVATE_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;
					break;
			}
		}
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_FIND;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((NULL == phObject) && (0 < ulMaxObjectCount))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	switch (pkcs11_mock_find_result)
	{
		case PKCS11_MOCK_CK_OBJECT_HANDLE_DATA:
			
			if (ulMaxObjectCount >= 2)
			{
				phObject[0] = pkcs11_mock_find_result;
				phObject[1] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 2;

			break;

		case CK_INVALID_HANDLE:
			
			*pulObjectCount = 0;

			break;

		default:

			if (ulMaxObjectCount >= 1)
			{
				phObject[0] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 1;

			break;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:

			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_RSA_PKCS_OAEP:

			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_DES3_CBC:

			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_AES_CBC:
			
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		default:

			return CKR_MECHANISM_INVALID;
	}

	switch (pkcs11_mock_active_operation)
	{
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_DIGEST:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_SIGN:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedData)
	{
		if (ulDataLen > *pulEncryptedDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulDataLen; i++)
				pEncryptedData[i] = pData[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulEncryptedDataLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastEncryptedPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastEncryptedPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:

			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_RSA_PKCS_OAEP:

			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_DES3_CBC:

			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_AES_CBC:
			
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		default:

			return CKR_MECHANISM_INVALID;
	}

	switch (pkcs11_mock_active_operation)
	{
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_DIGEST:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST;
			break;
		case PKCS11_MOCK_CK_OPERATION_VERIFY:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulEncryptedDataLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedDataLen; i++)
				pData[i] = pEncryptedData[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulDataLen = ulEncryptedDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_DECRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_SHA_1 != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	switch (pkcs11_mock_active_operation)
	{
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
			break;
		case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_DECRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(hash) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pDigest, hash, sizeof(hash));
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulDigestLen = sizeof(hash);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(hash) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pDigest, hash, sizeof(hash));

			switch (pkcs11_mock_active_operation)
			{
				case PKCS11_MOCK_CK_OPERATION_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
					break;
				case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
					break;
				case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
					break;
				default:
					return CKR_FUNCTION_FAILED;
			}
		}
	}

	*pulDigestLen = sizeof(hash);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));

			if (PKCS11_MOCK_CK_OPERATION_SIGN == pkcs11_mock_active_operation)
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
			else
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (ulDataLen > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulDataLen; i++)
				pSignature[i] = pData[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulSignatureLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulSignatureLen; i++)
				pData[i] = pSignature[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulDataLen = ulSignatureLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_DES3_KEY_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS_KEY_PAIR_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pPublicKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPublicKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pPrivateKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPrivateKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPublicKey)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPrivateKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (NULL == pPublicKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPublicKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	for (i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		if (NULL == pPrivateKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPrivateKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phPublicKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
	*phPrivateKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_BYTE wrappedKey[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hWrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL != pWrappedKey)
	{
		if (sizeof(wrappedKey) > *pulWrappedKeyLen)
			return CKR_BUFFER_TOO_SMALL;
		else
			memcpy(pWrappedKey, wrappedKey, sizeof(wrappedKey));
	}

	*pulWrappedKeyLen = sizeof(wrappedKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hUnwrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL == pWrappedKey)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulWrappedKeyLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulAttributeCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_XOR_BASE_AND_DATA != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL == pMechanism->pParameter) || (sizeof(CK_KEY_DERIVATION_STRING_DATA) != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hBaseKey)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 >= ulAttributeCount))
	{
		for (i = 0; i < ulAttributeCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSeed)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSeedLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == RandomData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	memset(RandomData, 1, ulRandomLen);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((0 != flags)  && (CKF_DONT_BLOCK != flags))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlot)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pReserved)
		return CKR_ARGUMENTS_BAD;

	return CKR_NO_EVENT;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetUnmanagedStructSizeList)(CK_ULONG_PTR pSizeList, CK_ULONG_PTR pulCount)
{
	CK_ULONG sizes[] = {
		sizeof(CK_ATTRIBUTE),
		sizeof(CK_C_INITIALIZE_ARGS),
		sizeof(CK_FUNCTION_LIST),
		sizeof(CK_INFO),
		sizeof(CK_MECHANISM),
		sizeof(CK_MECHANISM_INFO),
		sizeof(CK_SESSION_INFO),
		sizeof(CK_SLOT_INFO),
		sizeof(CK_TOKEN_INFO),
		sizeof(CK_VERSION),
		sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_AES_CTR_PARAMS),
		sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CTR_PARAMS),
		sizeof(CK_CMS_SIG_PARAMS),
		sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_ECDH1_DERIVE_PARAMS),
		sizeof(CK_ECDH2_DERIVE_PARAMS),
		sizeof(CK_ECMQV_DERIVE_PARAMS),
		sizeof(CK_EXTRACT_PARAMS),
		sizeof(CK_KEA_DERIVE_PARAMS),
		sizeof(CK_KEY_DERIVATION_STRING_DATA),
		sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS),
		sizeof(CK_KIP_PARAMS),
		sizeof(CK_MAC_GENERAL_PARAMS),
		sizeof(CK_OTP_PARAM),
		sizeof(CK_OTP_PARAMS),
		sizeof(CK_OTP_SIGNATURE_INFO),
		sizeof(CK_PBE_PARAMS),
		sizeof(CK_PKCS5_PBKD2_PARAMS),
		sizeof(CK_RC2_CBC_PARAMS),
		sizeof(CK_RC2_MAC_GENERAL_PARAMS),
		sizeof(CK_RC2_PARAMS),
		sizeof(CK_RC5_CBC_PARAMS),
		sizeof(CK_RC5_MAC_GENERAL_PARAMS),
		sizeof(CK_RC5_PARAMS),
		sizeof(CK_RSA_PKCS_OAEP_PARAMS),
		sizeof(CK_RSA_PKCS_PSS_PARAMS),
		sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS),
		sizeof(CK_SKIPJACK_RELAYX_PARAMS),
		sizeof(CK_SSL3_KEY_MAT_OUT),
		sizeof(CK_SSL3_KEY_MAT_PARAMS),
		sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_SSL3_RANDOM_DATA),
		sizeof(CK_TLS_PRF_PARAMS),
		sizeof(CK_WTLS_KEY_MAT_OUT),
		sizeof(CK_WTLS_KEY_MAT_PARAMS),
		sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_WTLS_PRF_PARAMS),
		sizeof(CK_WTLS_RANDOM_DATA),
		sizeof(CK_X9_42_DH1_DERIVE_PARAMS),
		sizeof(CK_X9_42_DH2_DERIVE_PARAMS),
		sizeof(CK_X9_42_MQV_DERIVE_PARAMS),
	};

	CK_ULONG sizes_count = sizeof(sizes) / sizeof(CK_ULONG);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSizeList)
	{
		*pulCount = sizes_count;
	}
	else
	{
		if (sizes_count > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		memcpy(pSizeList, sizes, sizeof(sizes));
		*pulCount = sizes_count;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EjectToken)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InteractiveLogin)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;

			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RW_USER_FUNCTIONS;

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}
