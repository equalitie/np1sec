/*
 * purple - Jabber XML parser stuff
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
 *
 */
#include "internal.h"

#include <libxml/parser.h>

#include "connection.h"
#include "debug.h"
#include "jabber.h"
#include "parser.h"
#include "util.h"
#include "xmlnode.h"

static void
jabber_parser_element_start_libxml(void *user_data,
				   const xmlChar *element_name, const xmlChar *prefix, const xmlChar *namespace,
				   int nb_namespaces, const xmlChar **namespaces,
				   int nb_attributes, int nb_defaulted, const xmlChar **attributes)
{
	JabberStream *js = user_data;
	xmlnode *node;
	int i, j;

	if(!element_name) {
		return;
	} else if (js->stream_id == NULL) {
		/* Sanity checking! */
		if (0 != xmlStrcmp(element_name, (xmlChar *) "stream") ||
				0 != xmlStrcmp(namespace, (xmlChar *) NS_XMPP_STREAMS)) {
			/* We were expecting a <stream:stream/> opening stanza, but
			 * didn't get it. Bad!
			 */
			purple_debug_error("jabber", "Expecting stream header, got %s with "
			                   "xmlns %s\n", element_name, namespace);
			purple_connection_error_reason(js->gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					_("XMPP stream header missing"));
			return;
		}

		js->protocol_version.major = 0;
		js->protocol_version.minor = 9;

		for (i = 0; i < nb_attributes * 5; i += 5) {
			int attrib_len = attributes[i+4] - attributes[i+3];
			char *attrib = g_strndup((gchar *)attributes[i+3], attrib_len);

			if(!xmlStrcmp(attributes[i], (xmlChar*) "version")) {
				const char *dot = strchr(attrib, '.');

				js->protocol_version.major = atoi(attrib);
				js->protocol_version.minor = dot ? atoi(dot + 1) : 0;

				if (js->protocol_version.major > 1) {
					/* TODO: Send <unsupported-version/> error */
					purple_connection_error_reason(js->gc,
							PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
							_("XMPP Version Mismatch"));
					g_free(attrib);
					return;
				}

				if (js->protocol_version.major == 0 && js->protocol_version.minor != 9) {
					purple_debug_warning("jabber", "Treating version %s as 0.9 for backward "
					                     "compatibility\n", attrib);
				}
				g_free(attrib);
			} else if(!xmlStrcmp(attributes[i], (xmlChar*) "id")) {
				g_free(js->stream_id);
				js->stream_id = attrib;
			} else {
				g_free(attrib);
			}
		}

		if (js->stream_id == NULL) {
#if 0
			/* This was underspecified in rfc3920 as only being a SHOULD, so
			 * we cannot rely on it.  See #12331 and Oracle's server.
			 */
			purple_connection_error_reason(js->gc,
					PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
					_("XMPP stream missing ID"));
#else
			/* Instead, let's make up a placeholder stream ID, which we need
			 * to do because we flag on it being NULL as a special case
			 * in this parsing code.
			 */
			js->stream_id = g_strdup("");
			purple_debug_info("jabber", "Server failed to specify a stream "
			                  "ID (underspecified in rfc3920, but intended "
			                  "to be a MUST; digest legacy auth may fail.\n");
#endif
		}
	} else {

		if(js->current)
			node = xmlnode_new_child(js->current, (const char*) element_name);
		else
			node = xmlnode_new((const char*) element_name);
		xmlnode_set_namespace(node, (const char*) namespace);
		xmlnode_set_prefix(node, (const char *)prefix);

		if (nb_namespaces != 0) {
			node->namespace_map = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);

			for (i = 0, j = 0; i < nb_namespaces; i++, j += 2) {
				const char *key = (const char *)namespaces[j];
				const char *val = (const char *)namespaces[j + 1];
				g_hash_table_insert(node->namespace_map,
					g_strdup(key ? key : ""), g_strdup(val ? val : ""));
			}
		}
		for(i=0; i < nb_attributes * 5; i+=5) {
			const char *name = (const char *)attributes[i];
			const char *prefix = (const char *)attributes[i+1];
			const char *attrib_ns = (const char *)attributes[i+2];
			char *txt;
			int attrib_len = attributes[i+4] - attributes[i+3];
			char *attrib = g_strndup((gchar *)attributes[i+3], attrib_len);

			txt = attrib;
			attrib = purple_unescape_text(txt);
			g_free(txt);
			xmlnode_set_attrib_full(node, name, attrib_ns, prefix, attrib);
			g_free(attrib);
		}

		js->current = node;
	}
}

static void
jabber_parser_element_end_libxml(void *user_data, const xmlChar *element_name,
				 const xmlChar *prefix, const xmlChar *namespace)
{
	JabberStream *js = user_data;

	if(!js->current)
		return;

	if(js->current->parent) {
		if(!xmlStrcmp((xmlChar*) js->current->name, element_name))
			js->current = js->current->parent;
	} else {
		xmlnode *packet = js->current;
		js->current = NULL;
		jabber_process_packet(js, &packet);
		if (packet != NULL)
			xmlnode_free(packet);
	}
}

static void
jabber_parser_element_text_libxml(void *user_data, const xmlChar *text, int text_len)
{
	JabberStream *js = user_data;

	if(!js->current)
		return;

	if(!text || !text_len)
		return;

	xmlnode_insert_data(js->current, (const char*) text, text_len);
}

static void
jabber_parser_structured_error_handler(void *user_data, xmlErrorPtr error)
{
	JabberStream *js = user_data;

	if (error->level == XML_ERR_WARNING && error->message != NULL
			&& g_str_equal(error->message, "xmlns: URI vcard-temp is not absolute\n"))
		/*
		 * This message happens when parsing vcards, and is normal, so don't
		 * bother logging it because people scare easily.
		 */
		return;

	if (error->level == XML_ERR_FATAL && error->code == XML_ERR_DOCUMENT_END)
		/*
		 * This is probably more annoying than the vcard-temp error; it occurs
		 * because we disconnect in most cases without waiting for the receiving
		 * </stream:stream> (limitations of libpurple)
		 */
		return;

	purple_debug_error("jabber", "XML parser error for JabberStream %p: "
								 "Domain %i, code %i, level %i: %s",
					   js,
					   error->domain, error->code, error->level,
					   (error->message ? error->message : "(null)\n"));
}

static xmlSAXHandler jabber_parser_libxml = {
	NULL,									/*internalSubset*/
	NULL,									/*isStandalone*/
	NULL,									/*hasInternalSubset*/
	NULL,									/*hasExternalSubset*/
	NULL,									/*resolveEntity*/
	NULL,									/*getEntity*/
	NULL,									/*entityDecl*/
	NULL,									/*notationDecl*/
	NULL,									/*attributeDecl*/
	NULL,									/*elementDecl*/
	NULL,									/*unparsedEntityDecl*/
	NULL,									/*setDocumentLocator*/
	NULL,									/*startDocument*/
	NULL,									/*endDocument*/
	NULL,									/*startElement*/
	NULL,									/*endElement*/
	NULL,									/*reference*/
	jabber_parser_element_text_libxml,		/*characters*/
	NULL,									/*ignorableWhitespace*/
	NULL,									/*processingInstruction*/
	NULL,									/*comment*/
	NULL,									/*warning*/
	NULL,									/*error*/
	NULL,									/*fatalError*/
	NULL,									/*getParameterEntity*/
	NULL,									/*cdataBlock*/
	NULL,									/*externalSubset*/
	XML_SAX2_MAGIC,							/*initialized*/
	NULL,									/*_private*/
	jabber_parser_element_start_libxml,		/*startElementNs*/
	jabber_parser_element_end_libxml,		/*endElementNs*/
	jabber_parser_structured_error_handler	/*serror*/
};

void
jabber_parser_setup(JabberStream *js)
{
	/* This seems backwards, but it makes sense. The libxml code creates
	 * the parser context when you try to use it (this way, it can figure
	 * out the encoding at creation time. So, setting up the parser is
	 * just a matter of destroying any current parser. */
	jabber_parser_free(js);
}

void jabber_parser_free(JabberStream *js) {
	if (js->context) {
		xmlParseChunk(js->context, NULL,0,1);
		xmlFreeParserCtxt(js->context);
		js->context = NULL;
	}
}

void jabber_parser_process(JabberStream *js, const char *buf, int len)
{
	int ret;

	if (js->context == NULL) {
		/* libxml inconsistently starts parsing on creating the
		 * parser, so do a ParseChunk right afterwards to force it. */
		js->context = xmlCreatePushParserCtxt(&jabber_parser_libxml, js, buf, len, NULL);
		xmlParseChunk(js->context, "", 0, 0);
	} else if ((ret = xmlParseChunk(js->context, buf, len, 0)) != XML_ERR_OK) {
		xmlError *err = xmlCtxtGetLastError(js->context);
		/*
		 * libxml2 uses a global setting to determine whether or not to store
		 * warnings.  Other libraries may set this, which causes err to be
		 * NULL. See #8136 for details.
		 */
		xmlErrorLevel level = XML_ERR_WARNING;

		if (err)
			level = err->level;

		switch (level) {
			case XML_ERR_NONE:
				purple_debug_info("jabber", "xmlParseChunk returned info %i\n", ret);
				break;
			case XML_ERR_WARNING:
				purple_debug_warning("jabber", "xmlParseChunk returned warning %i\n", ret);
				break;
			case XML_ERR_ERROR:
				purple_debug_error("jabber", "xmlParseChunk returned error %i\n", ret);
				break;
			case XML_ERR_FATAL:
				purple_debug_error("jabber", "xmlParseChunk returned fatal %i\n", ret);
				purple_connection_error_reason (js->gc,
				                                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				                                _("XML Parse error"));
				break;
		}
	}

	if (js->protocol_version.major == 0 && js->protocol_version.minor == 9 &&
			!js->gc->disconnect_timeout &&
			(js->state == JABBER_STREAM_INITIALIZING ||
			 js->state == JABBER_STREAM_INITIALIZING_ENCRYPTION)) {
		/*
		 * Legacy servers don't advertise features, so if we've just gotten
		 * the opening <stream:stream> and there was no version, we need to
		 * immediately start legacy IQ auth.
		 */
		jabber_stream_set_state(js, JABBER_STREAM_AUTHENTICATING);
		jabber_auth_start_old(js);
	}
}

