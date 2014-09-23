/**
 * @file upnp.c UPnP Implementation
 * @ingroup core
 */

/* purple
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */
#include "internal.h"

#include "upnp.h"

#include "debug.h"
#include "eventloop.h"
#include "network.h"
#include "proxy.h"
#include "signals.h"
#include "util.h"
#include "xmlnode.h"

/***************************************************************
** General Defines                                             *
****************************************************************/
#define HTTP_OK "200 OK"
#define DEFAULT_HTTP_PORT 80
#define DISCOVERY_TIMEOUT 1000
/* limit UPnP-triggered http downloads to 128k */
#define MAX_UPNP_DOWNLOAD (128 * 1024)

/***************************************************************
** Discovery/Description Defines                               *
****************************************************************/
#define NUM_UDP_ATTEMPTS 2

/* Address and port of an SSDP request used for discovery */
#define HTTPMU_HOST_ADDRESS "239.255.255.250"
#define HTTPMU_HOST_PORT 1900

#define SEARCH_REQUEST_DEVICE "urn:schemas-upnp-org:service:%s"

#define SEARCH_REQUEST_STRING \
	"M-SEARCH * HTTP/1.1\r\n" \
	"MX: 2\r\n" \
	"HOST: 239.255.255.250:1900\r\n" \
	"MAN: \"ssdp:discover\"\r\n" \
	"ST: urn:schemas-upnp-org:service:%s\r\n" \
	"\r\n"

#define WAN_IP_CONN_SERVICE "WANIPConnection:1"
#define WAN_PPP_CONN_SERVICE "WANPPPConnection:1"

/******************************************************************
** Action Defines                                                 *
*******************************************************************/
#define HTTP_HEADER_ACTION \
	"POST /%s HTTP/1.1\r\n" \
	"HOST: %s:%d\r\n" \
	"SOAPACTION: \"urn:schemas-upnp-org:service:%s#%s\"\r\n" \
	"CONTENT-TYPE: text/xml ; charset=\"utf-8\"\r\n" \
	"CONTENT-LENGTH: %" G_GSIZE_FORMAT "\r\n\r\n"

#define SOAP_ACTION \
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" \
	"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " \
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" \
	  "<s:Body>\r\n" \
	    "<u:%s xmlns:u=\"urn:schemas-upnp-org:service:%s\">\r\n" \
	      "%s" \
	    "</u:%s>\r\n" \
	  "</s:Body>\r\n" \
	"</s:Envelope>"

#define PORT_MAPPING_LEASE_TIME "0"
#define PORT_MAPPING_DESCRIPTION "PURPLE_UPNP_PORT_FORWARD"

#define ADD_PORT_MAPPING_PARAMS \
	"<NewRemoteHost></NewRemoteHost>\r\n" \
	"<NewExternalPort>%i</NewExternalPort>\r\n" \
	"<NewProtocol>%s</NewProtocol>\r\n" \
	"<NewInternalPort>%i</NewInternalPort>\r\n" \
	"<NewInternalClient>%s</NewInternalClient>\r\n" \
	"<NewEnabled>1</NewEnabled>\r\n" \
	"<NewPortMappingDescription>" \
	PORT_MAPPING_DESCRIPTION \
	"</NewPortMappingDescription>\r\n" \
	"<NewLeaseDuration>" \
	PORT_MAPPING_LEASE_TIME \
	"</NewLeaseDuration>\r\n"

#define DELETE_PORT_MAPPING_PARAMS \
	"<NewRemoteHost></NewRemoteHost>\r\n" \
	"<NewExternalPort>%i</NewExternalPort>\r\n" \
	"<NewProtocol>%s</NewProtocol>\r\n"

typedef enum {
	PURPLE_UPNP_STATUS_UNDISCOVERED = -1,
	PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER,
	PURPLE_UPNP_STATUS_DISCOVERING,
	PURPLE_UPNP_STATUS_DISCOVERED
} PurpleUPnPStatus;

typedef struct {
	PurpleUPnPStatus status;
	gchar* control_url;
	gchar service_type[20];
	char publicip[16];
	char internalip[16];
	time_t lookup_time;
} PurpleUPnPControlInfo;

typedef struct {
	guint inpa;	/* purple_input_add handle */
	guint tima;	/* purple_timeout_add handle */
	int fd;
	struct sockaddr_in server;
	gchar service_type[20];
	int retry_count;
	gchar *full_url;
} UPnPDiscoveryData;

struct _UPnPMappingAddRemove
{
	unsigned short portmap;
	gchar protocol[4];
	gboolean add;
	PurpleUPnPCallback cb;
	gpointer cb_data;
	gboolean success;
	guint tima; /* purple_timeout_add handle */
	PurpleUtilFetchUrlData *gfud;
};

static PurpleUPnPControlInfo control_info = {
	PURPLE_UPNP_STATUS_UNDISCOVERED,
	NULL, "\0", "\0", "\0", 0};

static GSList *discovery_callbacks = NULL;

static void purple_upnp_discover_send_broadcast(UPnPDiscoveryData *dd);
static void lookup_public_ip(void);
static void lookup_internal_ip(void);

static gboolean
fire_ar_cb_async_and_free(gpointer data)
{
	UPnPMappingAddRemove *ar = data;
	if (ar) {
		if (ar->cb)
			ar->cb(ar->success, ar->cb_data);
		g_free(ar);
	}

	return FALSE;
}

static void
fire_discovery_callbacks(gboolean success)
{
	while(discovery_callbacks) {
		gpointer data;
		PurpleUPnPCallback cb = discovery_callbacks->data;
		discovery_callbacks = g_slist_delete_link(discovery_callbacks, discovery_callbacks);
		data = discovery_callbacks->data;
		discovery_callbacks = g_slist_delete_link(discovery_callbacks, discovery_callbacks);
		cb(success, data);
	}
}

static gboolean
purple_upnp_compare_device(const xmlnode* device, const gchar* deviceType)
{
	xmlnode* deviceTypeNode = xmlnode_get_child(device, "deviceType");
	char *tmp;
	gboolean ret;

	if(deviceTypeNode == NULL) {
		return FALSE;
	}

	tmp = xmlnode_get_data(deviceTypeNode);
	ret = !g_ascii_strcasecmp(tmp, deviceType);
	g_free(tmp);

	return ret;
}

static gboolean
purple_upnp_compare_service(const xmlnode* service, const gchar* serviceType)
{
	xmlnode* serviceTypeNode;
	char *tmp;
	gboolean ret;

	if(service == NULL) {
		return FALSE;
	}

	serviceTypeNode = xmlnode_get_child(service, "serviceType");

	if(serviceTypeNode == NULL) {
		return FALSE;
	}

	tmp = xmlnode_get_data(serviceTypeNode);
	ret = !g_ascii_strcasecmp(tmp, serviceType);
	g_free(tmp);

	return ret;
}

static gchar*
purple_upnp_parse_description_response(const gchar* httpResponse, gsize len,
	const gchar* httpURL, const gchar* serviceType)
{
	gchar *xmlRoot, *baseURL, *controlURL, *service;
	xmlnode *xmlRootNode, *serviceTypeNode, *controlURLNode, *baseURLNode;
	char *tmp;

	/* make sure we have a valid http response */
	if(g_strstr_len(httpResponse, len, HTTP_OK) == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): Failed In HTTP_OK\n");
		return NULL;
	}

	/* find the root of the xml document */
	if((xmlRoot = g_strstr_len(httpResponse, len, "<root")) == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): Failed finding root\n");
		return NULL;
	}

	/* create the xml root node */
	if((xmlRootNode = xmlnode_from_str(xmlRoot,
			len - (xmlRoot - httpResponse))) == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): Could not parse xml root node\n");
		return NULL;
	}

	/* get the baseURL of the device */
	baseURL = NULL;
	if((baseURLNode = xmlnode_get_child(xmlRootNode, "URLBase")) != NULL) {
		baseURL = xmlnode_get_data(baseURLNode);
	}
	/* fixes upnp-descriptions with empty urlbase-element */
	if(baseURL == NULL){
		baseURL = g_strdup(httpURL);
	}

	/* get the serviceType child that has the service type as its data */

	/* get urn:schemas-upnp-org:device:InternetGatewayDevice:1 and its devicelist */
	serviceTypeNode = xmlnode_get_child(xmlRootNode, "device");
	while(!purple_upnp_compare_device(serviceTypeNode,
			"urn:schemas-upnp-org:device:InternetGatewayDevice:1") &&
			serviceTypeNode != NULL) {
		serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
	}
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 1\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "deviceList");
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 2\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}

	/* get urn:schemas-upnp-org:device:WANDevice:1 and its devicelist */
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "device");
	while(!purple_upnp_compare_device(serviceTypeNode,
			"urn:schemas-upnp-org:device:WANDevice:1") &&
			serviceTypeNode != NULL) {
		serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
	}
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 3\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "deviceList");
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 4\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}

	/* get urn:schemas-upnp-org:device:WANConnectionDevice:1 and its servicelist */
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "device");
	while(serviceTypeNode && !purple_upnp_compare_device(serviceTypeNode,
			"urn:schemas-upnp-org:device:WANConnectionDevice:1")) {
		serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
	}
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 5\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "serviceList");
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 6\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}

	/* get the serviceType variable passed to this function */
	service = g_strdup_printf(SEARCH_REQUEST_DEVICE, serviceType);
	serviceTypeNode = xmlnode_get_child(serviceTypeNode, "service");
	while(!purple_upnp_compare_service(serviceTypeNode, service) &&
			serviceTypeNode != NULL) {
		serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
	}

	g_free(service);
	if(serviceTypeNode == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): could not get serviceTypeNode 7\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}

	/* get the controlURL of the service */
	if((controlURLNode = xmlnode_get_child(serviceTypeNode,
			"controlURL")) == NULL) {
		purple_debug_error("upnp",
			"parse_description_response(): Could not find controlURL\n");
		g_free(baseURL);
		xmlnode_free(xmlRootNode);
		return NULL;
	}

	tmp = xmlnode_get_data(controlURLNode);
	if(baseURL && !purple_str_has_prefix(tmp, "http://") &&
	   !purple_str_has_prefix(tmp, "HTTP://")) {
		/* Handle absolute paths in a relative URL.  This probably
		 * belongs in util.c. */
		if (tmp[0] == '/') {
			size_t length;
			const char *path, *start = strstr(baseURL, "://");
			start = start ? start + 3 : baseURL;
			path = strchr(start, '/');
			length = path ? path - baseURL : strlen(baseURL);
			controlURL = g_strdup_printf("%.*s%s", (int)length, baseURL, tmp);
		} else {
			controlURL = g_strdup_printf("%s%s", baseURL, tmp);
		}
		g_free(tmp);
	}else{
		controlURL = tmp;
	}
	g_free(baseURL);
	xmlnode_free(xmlRootNode);

	return controlURL;
}

static void
upnp_parse_description_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
		const gchar *httpResponse, gsize len, const gchar *error_message)
{
	UPnPDiscoveryData *dd = user_data;
	gchar *control_url = NULL;

	if (len > 0)
		control_url = purple_upnp_parse_description_response(
			httpResponse, len, dd->full_url, dd->service_type);

	g_free(dd->full_url);

	if(control_url == NULL) {
		purple_debug_error("upnp",
			"purple_upnp_parse_description(): control URL is NULL\n");
	}

	control_info.status = control_url ? PURPLE_UPNP_STATUS_DISCOVERED
		: PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER;
	control_info.lookup_time = time(NULL);
	control_info.control_url = control_url;
	g_strlcpy(control_info.service_type, dd->service_type,
		sizeof(control_info.service_type));

	fire_discovery_callbacks(control_url != NULL);

	/* Look up the public and internal IPs */
	if(control_url != NULL) {
		lookup_public_ip();
		lookup_internal_ip();
	}

	if (dd->inpa > 0)
		purple_input_remove(dd->inpa);
	if (dd->tima > 0)
		purple_timeout_remove(dd->tima);

	g_free(dd);
}

static void
purple_upnp_parse_description(const gchar* descriptionURL, UPnPDiscoveryData *dd)
{
	gchar* httpRequest;
	gchar* descriptionXMLAddress;
	gchar* descriptionAddress;
	int port = 0;

	/* parse the 4 above variables out of the descriptionURL
	   example description URL: http://192.168.1.1:5678/rootDesc.xml */

	/* parse the url into address, port, path variables */
	if(!purple_url_parse(descriptionURL, &descriptionAddress,
			&port, &descriptionXMLAddress, NULL, NULL)) {
		return;
	}
	if(port == 0 || port == -1) {
		port = DEFAULT_HTTP_PORT;
	}

	/* for example...
	   GET /rootDesc.xml HTTP/1.1\r\nHost: 192.168.1.1:5678\r\n\r\n */
	httpRequest = g_strdup_printf(
		"GET /%s HTTP/1.1\r\n"
		"Connection: close\r\n"
		"Host: %s:%d\r\n\r\n",
		descriptionXMLAddress, descriptionAddress, port);

	g_free(descriptionXMLAddress);

	dd->full_url = g_strdup_printf("http://%s:%d",
			descriptionAddress, port);
	g_free(descriptionAddress);

	/* Remove the timeout because everything it is waiting for has
	 * successfully completed */
	purple_timeout_remove(dd->tima);
	dd->tima = 0;

	purple_util_fetch_url_request_len(descriptionURL, TRUE, NULL, TRUE, httpRequest,
			TRUE, MAX_UPNP_DOWNLOAD, upnp_parse_description_cb, dd);

	g_free(httpRequest);

}

static void
purple_upnp_parse_discover_response(const gchar* buf, unsigned int buf_len,
	UPnPDiscoveryData *dd)
{
	gchar* startDescURL;
	gchar* endDescURL;
	gchar* descURL;

	if(g_strstr_len(buf, buf_len, HTTP_OK) == NULL) {
		purple_debug_error("upnp",
			"parse_discover_response(): Failed In HTTP_OK\n");
		return;
	}

	if((startDescURL = g_strstr_len(buf, buf_len, "http://")) == NULL) {
		purple_debug_error("upnp",
			"parse_discover_response(): Failed In finding http://\n");
		return;
	}

	endDescURL = g_strstr_len(startDescURL, buf_len - (startDescURL - buf),
			"\r");
	if(endDescURL == NULL) {
		endDescURL = g_strstr_len(startDescURL,
				buf_len - (startDescURL - buf), "\n");
		if(endDescURL == NULL) {
			purple_debug_error("upnp",
				"parse_discover_response(): Failed In endDescURL\n");
			return;
		}
	}

	/* XXX: I'm not sure how this could ever happen */
	if(endDescURL == startDescURL) {
		purple_debug_error("upnp",
			"parse_discover_response(): endDescURL == startDescURL\n");
		return;
	}

	descURL = g_strndup(startDescURL, endDescURL - startDescURL);

	purple_upnp_parse_description(descURL, dd);

	g_free(descURL);

}

static gboolean
purple_upnp_discover_timeout(gpointer data)
{
	UPnPDiscoveryData* dd = data;

	if (dd->inpa)
		purple_input_remove(dd->inpa);
	if (dd->tima > 0)
		purple_timeout_remove(dd->tima);
	dd->inpa = 0;
	dd->tima = 0;

	if (dd->retry_count < NUM_UDP_ATTEMPTS) {
		/* TODO: We probably shouldn't be incrementing retry_count in two places */
		dd->retry_count++;
		purple_upnp_discover_send_broadcast(dd);
	} else {
		if (dd->fd != -1)
			close(dd->fd);

		control_info.status = PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER;
		control_info.lookup_time = time(NULL);
		control_info.service_type[0] = '\0';
		g_free(control_info.control_url);
		control_info.control_url = NULL;

		fire_discovery_callbacks(FALSE);

		g_free(dd);
	}

	return FALSE;
}

static void
purple_upnp_discover_udp_read(gpointer data, gint sock, PurpleInputCondition cond)
{
	int len;
	UPnPDiscoveryData *dd = data;
	gchar buf[65536];

	do {
		len = recv(dd->fd, buf,
			sizeof(buf) - 1, 0);

		if(len >= 0) {
			buf[len] = '\0';
			break;
		} else if(errno != EINTR) {
			/* We'll either get called again, or time out */
			return;
		}
	} while (errno == EINTR);

	purple_input_remove(dd->inpa);
	dd->inpa = 0;

	close(dd->fd);
	dd->fd = -1;

	/* parse the response, and see if it was a success */
	purple_upnp_parse_discover_response(buf, len, dd);

	/* We'll either time out or continue successfully */
}

static void
purple_upnp_discover_send_broadcast(UPnPDiscoveryData *dd)
{
	gchar *sendMessage = NULL;
	size_t totalSize;
	gboolean sentSuccess;

	/* because we are sending over UDP, if there is a failure
	   we should retry the send NUM_UDP_ATTEMPTS times. Also,
	   try different requests for WANIPConnection and WANPPPConnection*/
	for(; dd->retry_count < NUM_UDP_ATTEMPTS; dd->retry_count++) {
		sentSuccess = FALSE;

		if((dd->retry_count % 2) == 0) {
			g_strlcpy(dd->service_type, WAN_IP_CONN_SERVICE, sizeof(dd->service_type));
		} else {
			g_strlcpy(dd->service_type, WAN_PPP_CONN_SERVICE, sizeof(dd->service_type));
		}

		sendMessage = g_strdup_printf(SEARCH_REQUEST_STRING, dd->service_type);

		totalSize = strlen(sendMessage);

		do {
			if(sendto(dd->fd, sendMessage, totalSize, 0,
					(struct sockaddr*) &(dd->server),
					sizeof(struct sockaddr_in)
					) == totalSize) {
				sentSuccess = TRUE;
				break;
			}
		} while (errno == EINTR || errno == EAGAIN);

		g_free(sendMessage);

		if(sentSuccess) {
			dd->tima = purple_timeout_add(DISCOVERY_TIMEOUT,
				purple_upnp_discover_timeout, dd);
			dd->inpa = purple_input_add(dd->fd, PURPLE_INPUT_READ,
				purple_upnp_discover_udp_read, dd);

			return;
		}
	}

	/* We have already done all our retries. Make sure that the callback
	 * doesn't get called before the original function returns */
	dd->tima = purple_timeout_add(10, purple_upnp_discover_timeout, dd);
}

void
purple_upnp_discover(PurpleUPnPCallback cb, gpointer cb_data)
{
	/* Socket Setup Variables */
	int sock;
	struct hostent* hp;

	/* UDP RECEIVE VARIABLES */
	UPnPDiscoveryData *dd;

	if (control_info.status == PURPLE_UPNP_STATUS_DISCOVERING) {
		if (cb) {
			discovery_callbacks = g_slist_append(
					discovery_callbacks, cb);
			discovery_callbacks = g_slist_append(
					discovery_callbacks, cb_data);
		}
		return;
	}

	dd = g_new0(UPnPDiscoveryData, 1);
	if (cb) {
		discovery_callbacks = g_slist_append(discovery_callbacks, cb);
		discovery_callbacks = g_slist_append(discovery_callbacks,
				cb_data);
	}

	/* Set up the sockets */
	dd->fd = sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == -1) {
		purple_debug_error("upnp",
			"purple_upnp_discover(): Failed In sock creation\n");
		/* Short circuit the retry attempts */
		dd->retry_count = NUM_UDP_ATTEMPTS;
		dd->tima = purple_timeout_add(10, purple_upnp_discover_timeout, dd);
		return;
	}

	/* TODO: Non-blocking! */
	if((hp = gethostbyname(HTTPMU_HOST_ADDRESS)) == NULL) {
		purple_debug_error("upnp",
			"purple_upnp_discover(): Failed In gethostbyname\n");
		/* Short circuit the retry attempts */
		dd->retry_count = NUM_UDP_ATTEMPTS;
		dd->tima = purple_timeout_add(10, purple_upnp_discover_timeout, dd);
		return;
	}

	memset(&(dd->server), 0, sizeof(struct sockaddr));
	dd->server.sin_family = AF_INET;
	memcpy(&(dd->server.sin_addr), hp->h_addr_list[0], hp->h_length);
	dd->server.sin_port = htons(HTTPMU_HOST_PORT);

	control_info.status = PURPLE_UPNP_STATUS_DISCOVERING;

	purple_upnp_discover_send_broadcast(dd);
}

static PurpleUtilFetchUrlData*
purple_upnp_generate_action_message_and_send(const gchar* actionName,
		const gchar* actionParams, PurpleUtilFetchUrlCallback cb,
		gpointer cb_data)
{
	PurpleUtilFetchUrlData* gfud;
	gchar* soapMessage;
	gchar* totalSendMessage;
	gchar* pathOfControl;
	gchar* addressOfControl;
	int port = 0;

	/* parse the url into address, port, path variables */
	if(!purple_url_parse(control_info.control_url, &addressOfControl,
			&port, &pathOfControl, NULL, NULL)) {
		purple_debug_error("upnp",
			"generate_action_message_and_send(): Failed In Parse URL\n");
		/* XXX: This should probably be async */
		if(cb)
			cb(NULL, cb_data, NULL, 0, NULL);
		return NULL;
	}
	if(port == 0 || port == -1) {
		port = DEFAULT_HTTP_PORT;
	}

	/* set the soap message */
	soapMessage = g_strdup_printf(SOAP_ACTION, actionName,
		control_info.service_type, actionParams, actionName);

	/* set the HTTP Header, and append the body to it */
	totalSendMessage = g_strdup_printf(HTTP_HEADER_ACTION "%s",
		pathOfControl, addressOfControl, port,
		control_info.service_type, actionName,
		strlen(soapMessage), soapMessage);
	g_free(pathOfControl);
	g_free(soapMessage);

	gfud = purple_util_fetch_url_request_len(control_info.control_url, FALSE, NULL, TRUE,
				totalSendMessage, TRUE, MAX_UPNP_DOWNLOAD, cb, cb_data);

	g_free(totalSendMessage);
	g_free(addressOfControl);

	return gfud;
}

const gchar *
purple_upnp_get_public_ip()
{
	if (control_info.status == PURPLE_UPNP_STATUS_DISCOVERED
			&& strlen(control_info.publicip) > 0)
		return control_info.publicip;

	/* Trigger another UPnP discovery if 5 minutes have elapsed since the
	 * last one, and it wasn't successful */
	if (control_info.status < PURPLE_UPNP_STATUS_DISCOVERING
			&& (time(NULL) - control_info.lookup_time) > 300)
		purple_upnp_discover(NULL, NULL);

	return NULL;
}

static void
looked_up_public_ip_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
		const gchar *httpResponse, gsize len, const gchar *error_message)
{
	gchar* temp, *temp2;

	if ((error_message != NULL) || (httpResponse == NULL))
		return;

	/* extract the ip, or see if there is an error */
	if((temp = g_strstr_len(httpResponse, len,
			"<NewExternalIPAddress")) == NULL) {
		purple_debug_error("upnp",
			"looked_up_public_ip_cb(): Failed Finding <NewExternalIPAddress\n");
		return;
	}
	if(!(temp = g_strstr_len(temp, len - (temp - httpResponse), ">"))) {
		purple_debug_error("upnp",
			"looked_up_public_ip_cb(): Failed In Finding >\n");
		return;
	}
	if(!(temp2 = g_strstr_len(temp, len - (temp - httpResponse), "<"))) {
		purple_debug_error("upnp",
			"looked_up_public_ip_cb(): Failed In Finding <\n");
		return;
	}
	*temp2 = '\0';

	g_strlcpy(control_info.publicip, temp + 1,
			sizeof(control_info.publicip));

	purple_debug_info("upnp", "NAT Returned IP: %s\n", control_info.publicip);
}

static void
lookup_public_ip()
{
	purple_upnp_generate_action_message_and_send("GetExternalIPAddress", "",
			looked_up_public_ip_cb, NULL);
}

/* TODO: This could be exported */
static const gchar *
purple_upnp_get_internal_ip(void)
{
	if (control_info.status == PURPLE_UPNP_STATUS_DISCOVERED
			&& strlen(control_info.internalip) > 0)
		return control_info.internalip;

	/* Trigger another UPnP discovery if 5 minutes have elapsed since the
	 * last one, and it wasn't successful */
	if (control_info.status < PURPLE_UPNP_STATUS_DISCOVERING
			&& (time(NULL) - control_info.lookup_time) > 300)
		purple_upnp_discover(NULL, NULL);

	return NULL;
}

static void
looked_up_internal_ip_cb(gpointer data, gint source, const gchar *error_message)
{
	if (source != -1) {
		g_strlcpy(control_info.internalip,
			purple_network_get_local_system_ip(source),
			sizeof(control_info.internalip));
		purple_debug_info("upnp", "Local IP: %s\n",
				control_info.internalip);
		close(source);
	} else
		purple_debug_error("upnp", "Unable to look up local IP\n");

}

static void
lookup_internal_ip()
{
	gchar* addressOfControl;
	int port = 0;

	if(!purple_url_parse(control_info.control_url, &addressOfControl, &port,
			NULL, NULL, NULL)) {
		purple_debug_error("upnp",
			"lookup_internal_ip(): Failed In Parse URL\n");
		return;
	}
	if(port == 0 || port == -1) {
		port = DEFAULT_HTTP_PORT;
	}

	if(purple_proxy_connect(NULL, NULL, addressOfControl, port,
			looked_up_internal_ip_cb, NULL) == NULL)
	{
		purple_debug_error("upnp", "Get Local IP Connect Failed: Address: %s @@@ Port %d\n",
			addressOfControl, port);
	}

	g_free(addressOfControl);
}

static void
done_port_mapping_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
		const gchar *httpResponse, gsize len, const gchar *error_message)
{
	UPnPMappingAddRemove *ar = user_data;

	gboolean success = TRUE;

	/* determine if port mapping was a success */
	if ((error_message != NULL) || (httpResponse == NULL) ||
		(g_strstr_len(httpResponse, len, HTTP_OK) == NULL))
	{
		purple_debug_error("upnp",
			"purple_upnp_set_port_mapping(): Failed HTTP_OK\n%s\n",
			httpResponse ? httpResponse : "(null)");
		success =  FALSE;
	} else
		purple_debug_info("upnp", "Successfully completed port mapping operation\n");

	ar->success = success;
	ar->tima = purple_timeout_add(0, fire_ar_cb_async_and_free, ar);
}

static void
do_port_mapping_cb(gboolean has_control_mapping, gpointer data)
{
	UPnPMappingAddRemove *ar = data;

	if (has_control_mapping) {
		gchar action_name[25];
		gchar *action_params;
		if(ar->add) {
			const gchar *internal_ip;
			/* get the internal IP */
			if(!(internal_ip = purple_upnp_get_internal_ip())) {
				purple_debug_error("upnp",
					"purple_upnp_set_port_mapping(): couldn't get local ip\n");
				ar->success = FALSE;
				ar->tima = purple_timeout_add(0, fire_ar_cb_async_and_free, ar);
				return;
			}
			strncpy(action_name, "AddPortMapping",
					sizeof(action_name));
			action_params = g_strdup_printf(
					ADD_PORT_MAPPING_PARAMS,
					ar->portmap, ar->protocol, ar->portmap,
					internal_ip);
		} else {
			strncpy(action_name, "DeletePortMapping", sizeof(action_name));
			action_params = g_strdup_printf(
				DELETE_PORT_MAPPING_PARAMS,
				ar->portmap, ar->protocol);
		}

		ar->gfud = purple_upnp_generate_action_message_and_send(action_name,
						action_params, done_port_mapping_cb, ar);

		g_free(action_params);
		return;
	}

	ar->success = FALSE;
	ar->tima = purple_timeout_add(0, fire_ar_cb_async_and_free, ar);
}

static gboolean
fire_port_mapping_failure_cb(gpointer data)
{
	UPnPMappingAddRemove *ar = data;

	ar->tima = 0;
	do_port_mapping_cb(FALSE, data);
	return FALSE;
}

void purple_upnp_cancel_port_mapping(UPnPMappingAddRemove *ar)
{
	GSList *l;

	/* Remove ar from discovery_callbacks if present; it was inserted after a cb.
	 * The same cb may be in the list multiple times, so be careful to remove
	 * the one associated with ar. */
	l = discovery_callbacks;
	while (l)
	{
		GSList *next = l->next;

		if (next && (next->data == ar)) {
			discovery_callbacks = g_slist_delete_link(discovery_callbacks, next);
			next = l->next;
			discovery_callbacks = g_slist_delete_link(discovery_callbacks, l);
		}

		l = next;
	}

	if (ar->tima > 0)
		purple_timeout_remove(ar->tima);

	if (ar->gfud)
		purple_util_fetch_url_cancel(ar->gfud);

	g_free(ar);
}

UPnPMappingAddRemove *
purple_upnp_set_port_mapping(unsigned short portmap, const gchar* protocol,
		PurpleUPnPCallback cb, gpointer cb_data)
{
	UPnPMappingAddRemove *ar;

	ar = g_new0(UPnPMappingAddRemove, 1);
	ar->cb = cb;
	ar->cb_data = cb_data;
	ar->add = TRUE;
	ar->portmap = portmap;
	g_strlcpy(ar->protocol, protocol, sizeof(ar->protocol));

	/* If we're waiting for a discovery, add to the callbacks list */
	if(control_info.status == PURPLE_UPNP_STATUS_DISCOVERING) {
		/* TODO: This will fail because when this cb is triggered,
		 * the internal IP lookup won't be complete */
		discovery_callbacks = g_slist_append(
				discovery_callbacks, do_port_mapping_cb);
		discovery_callbacks = g_slist_append(
				discovery_callbacks, ar);
		return ar;
	}

	/* If we haven't had a successful UPnP discovery, check if 5 minutes has
	 * elapsed since the last try, try again */
	if(control_info.status == PURPLE_UPNP_STATUS_UNDISCOVERED ||
			(control_info.status == PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER
			 && (time(NULL) - control_info.lookup_time) > 300)) {
		purple_upnp_discover(do_port_mapping_cb, ar);
		return ar;
	} else if(control_info.status == PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER) {
		if (cb) {
			/* Asynchronously trigger a failed response */
			ar->tima = purple_timeout_add(10, fire_port_mapping_failure_cb, ar);
		} else {
			/* No need to do anything if nobody expects a response*/
			g_free(ar);
			ar = NULL;
		}
		return ar;
	}

	do_port_mapping_cb(TRUE, ar);
	return ar;
}

UPnPMappingAddRemove *
purple_upnp_remove_port_mapping(unsigned short portmap, const char* protocol,
		PurpleUPnPCallback cb, gpointer cb_data)
{
	UPnPMappingAddRemove *ar;

	ar = g_new0(UPnPMappingAddRemove, 1);
	ar->cb = cb;
	ar->cb_data = cb_data;
	ar->add = FALSE;
	ar->portmap = portmap;
	g_strlcpy(ar->protocol, protocol, sizeof(ar->protocol));

	/* If we're waiting for a discovery, add to the callbacks list */
	if(control_info.status == PURPLE_UPNP_STATUS_DISCOVERING) {
		discovery_callbacks = g_slist_append(
				discovery_callbacks, do_port_mapping_cb);
		discovery_callbacks = g_slist_append(
				discovery_callbacks, ar);
		return ar;
	}

	/* If we haven't had a successful UPnP discovery, check if 5 minutes has
	 * elapsed since the last try, try again */
	if(control_info.status == PURPLE_UPNP_STATUS_UNDISCOVERED ||
			(control_info.status == PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER
			 && (time(NULL) - control_info.lookup_time) > 300)) {
		purple_upnp_discover(do_port_mapping_cb, ar);
		return ar;
	} else if(control_info.status == PURPLE_UPNP_STATUS_UNABLE_TO_DISCOVER) {
		if (cb) {
			/* Asynchronously trigger a failed response */
			ar->tima = purple_timeout_add(10, fire_port_mapping_failure_cb, ar);
		} else {
			/* No need to do anything if nobody expects a response*/
			g_free(ar);
			ar = NULL;
		}
		return ar;
	}

	do_port_mapping_cb(TRUE, ar);
	return ar;
}

static void
purple_upnp_network_config_changed_cb(void *data)
{
	/* Reset the control_info to default values */
	control_info.status = PURPLE_UPNP_STATUS_UNDISCOVERED;
	g_free(control_info.control_url);
	control_info.control_url = NULL;
	control_info.service_type[0] = '\0';
	control_info.publicip[0] = '\0';
	control_info.internalip[0] = '\0';
	control_info.lookup_time = 0;
}

static void*
purple_upnp_get_handle(void)
{
	static int handle;

	return &handle;
}

void
purple_upnp_init()
{
	purple_signal_connect(purple_network_get_handle(), "network-configuration-changed",
						  purple_upnp_get_handle(), PURPLE_CALLBACK(purple_upnp_network_config_changed_cb),
						  NULL);
}
