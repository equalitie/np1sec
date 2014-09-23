/*
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#include "win32dep.h"
#include "dns_sd_proxy.h"

#ifndef LINK_DNS_SD_DIRECTLY
static DNSServiceErrorType (DNSSD_API* _DNSServiceAddRecord)(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags,
		uint16_t rrtype, uint16_t rdlen, const void *rdata, uint32_t ttl);
static DNSServiceErrorType (DNSSD_API* _DNSServiceBrowse)(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	const char *regtype, const char *domain, DNSServiceBrowseReply callBack, void *context);
static int (DNSSD_API* _DNSServiceConstructFullName)(char *fullName, const char *service, const char *regtype, const char *domain);
static DNSServiceErrorType (DNSSD_API* _DNSServiceGetAddrInfo)(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	DNSServiceProtocol protocol, const char *hostname, DNSServiceGetAddrInfoReply callBack, void *context);
static DNSServiceErrorType (DNSSD_API* _DNSServiceProcessResult)(DNSServiceRef sdRef);
static DNSServiceErrorType (DNSSD_API* _DNSServiceQueryRecord)(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	const char *fullname, uint16_t rrtype, uint16_t rrclass, DNSServiceQueryRecordReply callBack, void *context);
static void (DNSSD_API* _DNSServiceRefDeallocate)(DNSServiceRef sdRef);
static int (DNSSD_API* _DNSServiceRefSockFD)(DNSServiceRef sdRef);
static DNSServiceErrorType (DNSSD_API* _DNSServiceRegister)(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
	const char *name, const char *regtype, const char *domain, const char *host, uint16_t port, uint16_t txtLen,
	const void *txtRecord, DNSServiceRegisterReply callBack, void *context);
static DNSServiceErrorType (DNSSD_API* _DNSServiceResolve)(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name,
	const char *regtype, const char *domain, DNSServiceResolveReply callBack, void *context);
static DNSServiceErrorType (DNSSD_API* _DNSServiceRemoveRecord)(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags);
static DNSServiceErrorType (DNSSD_API* _DNSServiceUpdateRecord)(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags,
	uint16_t rdlen, const void *rdata, uint32_t ttl);
static void (DNSSD_API* _TXTRecordCreate)(TXTRecordRef *txtRecord, uint16_t bufferLen, void *buffer);
static void (DNSSD_API* _TXTRecordDeallocate)(TXTRecordRef *txtRecord);
static const void * (DNSSD_API* _TXTRecordGetBytesPtr)(const TXTRecordRef *txtRecord);
static int16_t (DNSSD_API* _TXTRecordGetLength)(const TXTRecordRef *txtRecord);
static const void * (DNSSD_API* _TXTRecordGetValuePtr)(uint16_t txtLen, const void *txtRecord, const char *key, uint8_t *valueLen);
static DNSServiceErrorType (DNSSD_API* _TXTRecordSetValue)(TXTRecordRef *txtRecord, const char *key, uint8_t valueSize, const void *value);

#endif

gboolean dns_sd_available(void) {
#ifndef LINK_DNS_SD_DIRECTLY
	static gboolean initialized = FALSE;
	static gboolean loaded = FALSE;

	if (!initialized) {
		initialized = TRUE;
		if ((_DNSServiceAddRecord = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceAddRecord"))
				&& (_DNSServiceBrowse = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceBrowse"))
				&& (_DNSServiceConstructFullName = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceConstructFullName"))
				&& (_DNSServiceGetAddrInfo = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceGetAddrInfo"))
				&& (_DNSServiceProcessResult = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceProcessResult"))
				&& (_DNSServiceQueryRecord = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceQueryRecord"))
				&& (_DNSServiceRefDeallocate = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceRefDeallocate"))
				&& (_DNSServiceRefSockFD = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceRefSockFD"))
				&& (_DNSServiceRegister = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceRegister"))
				&& (_DNSServiceResolve = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceResolve"))
				&& (_DNSServiceRemoveRecord = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceRemoveRecord"))
				&& (_DNSServiceUpdateRecord = (void *) wpurple_find_and_loadproc("dnssd.dll", "DNSServiceUpdateRecord"))
				&& (_TXTRecordCreate = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordCreate"))
				&& (_TXTRecordDeallocate = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordDeallocate"))
				&& (_TXTRecordGetBytesPtr = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordGetBytesPtr"))
				&& (_TXTRecordGetLength = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordGetLength"))
				&& (_TXTRecordGetValuePtr = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordGetValuePtr"))
				&& (_TXTRecordSetValue = (void *) wpurple_find_and_loadproc("dnssd.dll", "TXTRecordSetValue"))) {
			loaded = TRUE;
		}
	}
	return loaded;
#else
	return TRUE;
#endif
}

#ifndef LINK_DNS_SD_DIRECTLY

DNSServiceErrorType _wpurple_DNSServiceAddRecord(DNSServiceRef sdRef, DNSRecordRef *RecordRef, DNSServiceFlags flags,
		uint16_t rrtype, uint16_t rdlen, const void *rdata, uint32_t ttl) {
	g_return_val_if_fail(_DNSServiceAddRecord != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceAddRecord)(sdRef, RecordRef, flags, rrtype, rdlen, rdata, ttl);
}

DNSServiceErrorType _wpurple_DNSServiceBrowse(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
		const char *regtype, const char *domain, DNSServiceBrowseReply callBack, void *context) {
	g_return_val_if_fail(_DNSServiceBrowse != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceBrowse)(sdRef, flags, interfaceIndex, regtype, domain, callBack, context);
}

int _wpurple_DNSServiceConstructFullName(char *fullName, const char *service, const char *regtype, const char *domain) {
	g_return_val_if_fail(_DNSServiceConstructFullName != NULL, 0);
	return (_DNSServiceConstructFullName)(fullName, service, regtype, domain);
}

DNSServiceErrorType _wpurple_DNSServiceGetAddrInfo(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
		DNSServiceProtocol protocol, const char *hostname, DNSServiceGetAddrInfoReply callBack, void *context) {
	g_return_val_if_fail(_DNSServiceGetAddrInfo != NULL, 0);
	return (_DNSServiceGetAddrInfo)(sdRef, flags, interfaceIndex, protocol, hostname, callBack, context);
}

DNSServiceErrorType _wpurple_DNSServiceProcessResult(DNSServiceRef sdRef) {
	g_return_val_if_fail(_DNSServiceProcessResult != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceProcessResult)(sdRef);
}


DNSServiceErrorType _wpurple_DNSServiceQueryRecord(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
		const char *fullname, uint16_t rrtype, uint16_t rrclass, DNSServiceQueryRecordReply callBack, void *context) {
	g_return_val_if_fail(_DNSServiceQueryRecord != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceQueryRecord)(sdRef, flags, interfaceIndex, fullname, rrtype, rrclass, callBack, context);
}

void _wpurple_DNSServiceRefDeallocate(DNSServiceRef sdRef) {
	g_return_if_fail(_DNSServiceRefDeallocate != NULL);
	(_DNSServiceRefDeallocate)(sdRef);
}

int _wpurple_DNSServiceRefSockFD(DNSServiceRef sdRef) {
	g_return_val_if_fail(_DNSServiceRefSockFD != NULL, -1);
	return (_DNSServiceRefSockFD)(sdRef);
}

DNSServiceErrorType _wpurple_DNSServiceRegister(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
		const char *name, const char *regtype, const char *domain, const char *host, uint16_t port, uint16_t txtLen,
		const void *txtRecord, DNSServiceRegisterReply callBack, void *context) {
	g_return_val_if_fail(_DNSServiceRegister != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceRegister)(sdRef, flags, interfaceIndex, name, regtype, domain, host, port, txtLen, txtRecord, callBack, context);
}

DNSServiceErrorType _wpurple_DNSServiceResolve(DNSServiceRef *sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, const char *name,
		const char *regtype, const char *domain, DNSServiceResolveReply callBack, void *context) {
	g_return_val_if_fail(_DNSServiceResolve != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceResolve)(sdRef, flags, interfaceIndex, name, regtype, domain, callBack, context);
}

DNSServiceErrorType _wpurple_DNSServiceRemoveRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags) {
	g_return_val_if_fail(_DNSServiceRemoveRecord != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceRemoveRecord)(sdRef, RecordRef, flags);
}

DNSServiceErrorType _wpurple_DNSServiceUpdateRecord(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags,
		uint16_t rdlen, const void *rdata, uint32_t ttl) {
	g_return_val_if_fail(_DNSServiceUpdateRecord != NULL, kDNSServiceErr_Unknown);
	return (_DNSServiceUpdateRecord)(sdRef, RecordRef, flags, rdlen, rdata, ttl);
}

void _wpurple_TXTRecordCreate(TXTRecordRef *txtRecord, uint16_t bufferLen, void *buffer) {
	g_return_if_fail(_TXTRecordCreate != NULL);
	(_TXTRecordCreate)(txtRecord, bufferLen, buffer);
}

void _wpurple_TXTRecordDeallocate(TXTRecordRef *txtRecord) {
	g_return_if_fail(_TXTRecordDeallocate != NULL);
	(_TXTRecordDeallocate)(txtRecord);
}

const void * _wpurple_TXTRecordGetBytesPtr(const TXTRecordRef *txtRecord) {
	g_return_val_if_fail(_TXTRecordGetBytesPtr != NULL, NULL);
	return (_TXTRecordGetBytesPtr)(txtRecord);
}

uint16_t _wpurple_TXTRecordGetLength(const TXTRecordRef *txtRecord) {
	g_return_val_if_fail(_TXTRecordGetLength != NULL, 0);
	return (_TXTRecordGetLength)(txtRecord);
}

const void * _wpurple_TXTRecordGetValuePtr(uint16_t txtLen, const void *txtRecord, const char *key, uint8_t *valueLen) {
	g_return_val_if_fail(_TXTRecordGetValuePtr != NULL, NULL);
	return (_TXTRecordGetValuePtr)(txtLen, txtRecord, key, valueLen);
}

DNSServiceErrorType _wpurple_TXTRecordSetValue(TXTRecordRef *txtRecord, const char *key, uint8_t valueSize, const void *value) {
	g_return_val_if_fail(_TXTRecordSetValue != NULL, kDNSServiceErr_Unknown);
	return (_TXTRecordSetValue)(txtRecord, key, valueSize, value);
}

#endif /*LINK_DNS_SD_DIRECTLY*/

