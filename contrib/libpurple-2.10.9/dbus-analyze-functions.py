from __future__ import print_function
import re
import string
import sys

# types translated into "int"
simpletypes = ["int", "gint", "guint", "gboolean", "size_t", "gssize", "time_t"]

# List "excluded" contains functions that shouldn't be exported via
# DBus.  If you remove a function from this list, please make sure
# that it does not break "make" with the configure option
# "--enable-dbus" turned on.

excluded = [\
    # I don't remember why this function is excluded; something to do
    # with the fact that it takes a (const) GList as a parameter.
    "purple_presence_add_list",

    # These functions are excluded because they involve value of the
    # type PurpleConvPlacementFunc, which is a pointer to a function and
    # (currently?) can't be translated into a DBus type.  Normally,
    # functions with untranslatable types are skipped, but this script
    # assumes that all non-pointer type names beginning with "Purple"
    # are enums, which is not true in this case.
    "purple_conv_placement_add_fnc",
    "purple_conv_placement_get_fnc",
    "purple_conv_placement_get_current_func",
    "purple_conv_placement_set_current_func",

    # Similar to the above:
    "purple_account_set_register_callback",
    "purple_account_unregister",
    "purple_connection_new_unregister",

    # These functions are excluded because they involve setting arbitrary
    # data via pointers for protocols and UIs.  This just won't work.
    "purple_blist_get_ui_data",
    "purple_blist_set_ui_data",
    "purple_blist_node_get_ui_data",
    "purple_blist_node_set_ui_data",
    "purple_buddy_get_protocol_data",
    "purple_buddy_set_protocol_data",

    # This is excluded because this script treats PurpleLogReadFlags*
    # as pointer to a struct, instead of a pointer to an enum.  This
    # causes a compilation error. Someone should fix this script.
    "purple_log_read",
    ]

# This is a list of functions that return a GList* or GSList * whose elements
# are strings, not pointers to objects.
stringlists = [
    "purple_prefs_get_path_list",
    "purple_prefs_get_string_list",
    "purple_uri_list_extract_filenames",
    "purple_uri_list_extract_uris",
    "purple_prefs_get_children_names",
]

# This is a list of functions that return a GList* or GSList* that should
# not be freed.  Ideally, this information should be obtained from the Doxygen
# documentation at some point.
constlists = [
    "purple_account_get_status_types",
    "purple_accounts_get_all",
    "purple_account_option_get_list",
    "purple_connections_get_all",
    "purple_connections_get_connecting",
    "purple_get_conversations",
    "purple_get_ims",
    "purple_get_chats",
    "purple_conv_chat_get_users",
    "purple_conv_chat_get_ignored",
    "purple_mime_document_get_fields",
    "purple_mime_document_get_parts",
    "purple_mime_part_get_fields",
    "purple_notify_user_info_get_entries",
    "purple_request_fields_get_required",
    "purple_request_field_list_get_selected",
    "purple_request_field_list_get_items",
    "purple_savedstatuses_get_all",
    "purple_status_type_get_attrs",
    "purple_presence_get_statuses",
    "purple_conversation_get_message_history",
]

pointer = "#pointer#"

class MyException(Exception):
    pass

myexception = MyException()

def ctopascal(name):
    newname = ""
    for word in name.split("_"):
        newname += word.capitalize()
    return newname

class Parameter:
    def __init__(self, type, name):
        self.name = name
        self.type = type

    def fromtokens(tokens, parameternumber = -1):
        if len(tokens) == 0:
            raise myexception
        if (len(tokens) == 1) or (tokens[-1] == pointer):
            if parameternumber >= 0:
                return Parameter(tokens, "param%i" % parameternumber)
            else:
                raise myexception
        else:
            return Parameter(tokens[:-1], tokens[-1])
                    
    fromtokens = staticmethod(fromtokens)

class Binding:
    def __init__(self, functiontext, paramtexts):
        self.function = Parameter.fromtokens(functiontext.split())

        if self.function.name in excluded:
            raise myexception

        self.params = []
        for i in range(len(paramtexts)):
            self.params.append(Parameter.fromtokens(paramtexts[i].split(), i))

        self.call = "%s(%s)" % (self.function.name,
                                ", ".join(param.name for param in self.params))
        
    
    def process(self):
        for param in self.params:
            self.processinput(param.type, param.name)

        self.processoutput(self.function.type, "RESULT")
        self.flush()
        

    def processinput(self, type, name):
        const = False
        unsigned = False
        if type[0] == "const":
            type = type[1:]
            const = True

        if type[0] == "unsigned":
            type = type[1:]
            unsigned = True

        if len(type) == 1:
            # simple types (int, gboolean, etc.) and enums
            if (type[0] in simpletypes) or ((type[0].startswith("Purple") and not type[0].endswith("Callback"))):
                return self.inputsimple(type, name, unsigned)

        # pointers ... 
        if (len(type) == 2) and (type[1] == pointer):
            # strings
            if type[0] in ["char", "gchar"]:
                if const:
                    return self.inputstring(type, name, unsigned)
                else:
                    raise myexception

            elif type[0] == "GHashTable":
                return self.inputhash(type, name)
                
            # known object types are transformed to integer handles
            elif type[0].startswith("Purple") or type[0] == "xmlnode":
                return self.inputpurplestructure(type, name)

            # special case for *_get_data functions, be careful here...
            elif (type[0] == "size_t" or type[0] == "gsize") and name == "len":
                return self.inputgetdata(type, name)
            
            # unknown pointers are always replaced with NULL
            else:
                return self.inputpointer(type, name)

        raise myexception

   
    def processoutput(self, type, name):
        const = False
        unsigned = False
        # the "void" type is simple ...
        if type == ["void"]:
            return self.outputvoid(type, name)

        if type[0] == "const":
            type = type[1:]
            const = True

        if type[0] == "unsigned":
            type = type[1:]
            unsigned = True

        # a string
        if type == ["char", pointer] or type == ["gchar", pointer]:
            return self.outputstring(type, name, const)

        # simple types (ints, booleans, enums, ...)
        if (len(type) == 1) and \
               ((type[0] in simpletypes) or (type[0].startswith("Purple"))):
            return self.outputsimple(type, name, unsigned)

        # pointers ...
        if (len(type) == 2) and (type[1] == pointer):

            # handles
            if type[0].startswith("Purple"):
                return self.outputpurplestructure(type, name)

            if type[0] in ["GList", "GSList"]:
                return self.outputlist(type, name)

        # Special case for *_get_data functions
        if type[0] == "gconstpointer":
            return self.outputgetdata(type, name)

        raise myexception
    

class ClientBinding (Binding):
    def __init__(self, functiontext, paramtexts, knowntypes, headersonly):
        Binding.__init__(self, functiontext, paramtexts)
        self.knowntypes = knowntypes
        self.headersonly = headersonly
        self.paramshdr = []
        self.decls = []
        self.inputparams = []
        self.outputparams = []
        self.returncode = []

    def flush(self):
        paramslist = ", ".join(self.paramshdr)
        if (paramslist == "") :
            paramslist = "void"
        print("%s %s(%s)" % (self.functiontype, self.function.name,
                             paramslist), end=' ')

        if self.headersonly:
            print(";")
            return

        print("{")

        for decl in self.decls:
            print(decl)

        print('dbus_g_proxy_call(purple_proxy, "%s", NULL,' % ctopascal(self.function.name))
        
        for type_name in self.inputparams:
            print("\t%s, %s, " % type_name, end=' ')
        print("G_TYPE_INVALID,")

        for type_name in self.outputparams:
            print("\t%s, &%s, " % type_name, end=' ')
        print("G_TYPE_INVALID);")
        
        for code in self.returncode:
            print(code)

        print("}\n")
        

    def definepurplestructure(self, type):
        if (self.headersonly) and (type[0] not in self.knowntypes):
            print("struct _%s;" % type[0])
            print("typedef struct _%s %s;" % (type[0], type[0]))
            self.knowntypes.append(type[0])

    def inputsimple(self, type, name, us):
        self.paramshdr.append("%s %s" % (type[0], name))
        if us:
            self.inputparams.append(("G_TYPE_UINT", name))
        else:
            self.inputparams.append(("G_TYPE_INT", name))

    def inputstring(self, type, name, us):
        if us:
            self.paramshdr.append("const unsigned char *%s" % name)
        else:
            self.paramshdr.append("const char *%s" % name)
        self.inputparams.append(("G_TYPE_STRING", name))
        
    def inputpurplestructure(self, type, name):
        self.paramshdr.append("const %s *%s" % (type[0], name))
        self.inputparams.append(("G_TYPE_INT", "GPOINTER_TO_INT(%s)" % name))
        self.definepurplestructure(type)

    def inputpointer(self, type, name):
        name += "_NULL"
        self.paramshdr.append("const %s *%s" % (type[0], name))
        self.inputparams.append(("G_TYPE_INT", "0"))
        
    def inputhash(self, type, name):
        self.paramshdr.append("const GHashTable *%s" % name)
        self.inputparams.append(('dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_STRING)', name))

    def outputvoid(self, type, name):
        self.functiontype = "void"

    def outputstring(self, type, name, const):
        self.functiontype = "char*"
        self.decls.append("char *%s = NULL;" % name)
        self.outputparams.append(("G_TYPE_STRING", name))
#        self.returncode.append("NULLIFY(%s);" % name)
        self.returncode.append("return %s;" % name);

    def outputsimple(self, type, name, us):
        self.functiontype = type[0]
        self.decls.append("%s %s = 0;" % (type[0], name))
        if us:
            self.outputparams.append(("G_TYPE_UINT", name))
        else:
            self.outputparams.append(("G_TYPE_INT", name))
        self.returncode.append("return %s;" % name);

    # we could add "const" to the return type but this would probably
    # be a nuisance
    def outputpurplestructure(self, type, name):
        name = name + "_ID"
        self.functiontype = "%s*" % type[0]
        self.decls.append("int %s = 0;" % name)
        self.outputparams.append(("G_TYPE_INT", "%s" % name))
        self.returncode.append("return (%s*) GINT_TO_POINTER(%s);" % (type[0], name));
        self.definepurplestructure(type)

    def outputlist(self, type, name):
        self.functiontype = "%s*" % type[0]
        self.decls.append("GArray *%s;" % name)
        self.outputparams.append(('dbus_g_type_get_collection("GArray", G_TYPE_INT)', name))
        self.returncode.append("return garray_int_to_%s(%s);" %
                               (type[0].lower(), name));

    # Special case for *_get_data functions, don't need client bindings,
    #  but do need the name so it doesn't crash
    def inputgetdata(self, type, name):
        raise myexception
    def outputgetdata(self, type, name):
        raise myexception

class ServerBinding (Binding):
    def __init__(self, functiontext, paramtexts):
        Binding.__init__(self, functiontext, paramtexts)
        self.dparams = ""
        self.cparams = []
        self.cdecls  = []
        self.ccode  = []
        self.cparamsout = []
        self.ccodeout = []
        self.argfunc = "dbus_message_get_args"

    def flush(self):
        print("static DBusMessage*")
        print("%s_DBUS(DBusMessage *message_DBUS, DBusError *error_DBUS) {" % \
              self.function.name)
        
        print("\tDBusMessage *reply_DBUS;")

        for decl in self.cdecls:
            print(decl)

        print("\t%s(message_DBUS, error_DBUS," % self.argfunc,end=' ')
        for param in self.cparams:
            print("DBUS_TYPE_%s, &%s," % param, end=' ')
        print("DBUS_TYPE_INVALID);")

        print("\tCHECK_ERROR(error_DBUS);")

        for code in self.ccode:
            print(code)

        print("\treply_DBUS = dbus_message_new_method_return (message_DBUS);")

        print("\tdbus_message_append_args(reply_DBUS,", end=' ')
        for param in self.cparamsout:
            if type(param) is str:
                print("%s," % param, end=' ')
            else:
                print("DBUS_TYPE_%s, &%s," % param, end=' ')
        print("DBUS_TYPE_INVALID);")

        for code in self.ccodeout:
            print(code)

        print("\treturn reply_DBUS;\n}\n")


    def addstring(self, *items):
        for item in items:
            self.dparams += item + r"\0"

    def addintype(self, type, name):
        self.addstring("in", type, name)

    def addouttype(self, type, name):
        self.addstring("out", type, name)


    # input parameters

    def inputsimple(self, type, name, us):
        if us:
            self.cdecls.append("\tdbus_uint32_t %s;" % name)
            self.cparams.append(("UINT32", name))
            self.addintype("u", name)
        else:
            self.cdecls.append("\tdbus_int32_t %s;" % name)
            self.cparams.append(("INT32", name))
            self.addintype("i", name)

    def inputstring(self, type, name, us):
        if us:
            self.cdecls.append("\tconst unsigned char *%s;" % name)
        else:
            self.cdecls.append("\tconst char *%s;" % name)
        self.cparams.append(("STRING", name))
        self.ccode.append("\t%s = (%s && %s[0]) ? %s : NULL;" % (name,name,name,name))
        self.addintype("s", name)

    def inputhash(self, type, name):
        self.argfunc = "purple_dbus_message_get_args"
        self.cdecls.append("\tDBusMessageIter %s_ITER;" % name)
        self.cdecls.append("\tGHashTable *%s;" % name)
        self.cparams.append(("ARRAY", "%s_ITER" % name))
        self.ccode.append("\t%s = purple_dbus_iter_hash_table(&%s_ITER, error_DBUS);" \
                     % (name, name))
        self.ccode.append("\tCHECK_ERROR(error_DBUS);")
        self.ccodeout.append("\tg_hash_table_destroy(%s);" % name)
        self.addintype("a{ss}", name)

    def inputpurplestructure(self, type, name):
        self.cdecls.append("\tdbus_int32_t %s_ID;" %  name)
        self.cdecls.append("\t%s *%s;" % (type[0], name))
        self.cparams.append(("INT32", name + "_ID"))
        self.ccode.append("\tPURPLE_DBUS_ID_TO_POINTER(%s, %s_ID, %s, error_DBUS);"  % \
                          (name, name, type[0]))
        self.addintype("i", name)

    def inputpointer(self, type, name):
        self.cdecls.append("\tdbus_int32_t %s_NULL;" %  name)
        self.cdecls .append("\t%s *%s;" % (type[0], name))
        self.cparams.append(("INT32", name + "_NULL"))
        self.ccode  .append("\t%s = NULL;" % name)
        self.addintype("i", name)

    # output parameters

    def outputvoid(self, type, name):
        self.ccode.append("\t%s;" % self.call) # just call the function

    def outputstring(self, type, name, const):
        if const:
            self.cdecls.append("\tconst char *%s;" % name)
        else:
            self.cdecls.append("\tchar *%s;" % name)
        self.ccode.append("\tif ((%s = %s) == NULL)" % (name, self.call))
        self.ccode.append("\t\t%s = \"\";" % (name))
        self.cparamsout.append(("STRING", name))
        self.addouttype("s", name)
        if not const:
            self.ccodeout.append("\tg_free(%s);" % name)

    def outputsimple(self, type, name, us):
        if us:
            self.cdecls.append("\tdbus_uint32_t %s;" % name)
            self.cparamsout.append(("UINT32", name))
            self.addouttype("u", name)
        else:
            self.cdecls.append("\tdbus_int32_t %s;" % name)
            self.cparamsout.append(("INT32", name))
            self.addouttype("i", name)
        self.ccode.append("\t%s = %s;" % (name, self.call))

    def outputpurplestructure(self, type, name):
        self.cdecls.append("\tdbus_int32_t %s;" % name)
        self.ccode .append("\tPURPLE_DBUS_POINTER_TO_ID(%s, %s, error_DBUS);" % (name, self.call))
        self.cparamsout.append(("INT32", name))
        self.addouttype("i", name)

    # GList*, GSList*, assume that list is a list of objects
    # unless the function is in stringlists
    def outputlist(self, type, name):
        self.cdecls.append("\tdbus_int32_t %s_LEN;" % name)
        self.ccodeout.append("\tg_free(%s);" % name)

        self.cdecls.append("\t%s *list;" % type[0]);

        if self.function.name in stringlists:
            self.cdecls.append("\tchar **%s;" % name)
            self.ccode.append("\tlist = %s;" % self.call)
            self.ccode.append("\t%s = (char **)purple_%s_to_array(list, FALSE, &%s_LEN);" % \
                         (name, type[0], name))
            self.cparamsout.append("DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &%s, %s_LEN" \
                          % (name, name))
            if (not (self.function.name in constlists)):
                type_name = type[0].lower()[1:]
                self.ccodeout.append("\tg_%s_foreach(list, (GFunc)g_free, NULL);" % type_name)
                self.ccodeout.append("\tg_%s_free(list);" % type_name)
            self.addouttype("as", name)
        else:
            self.cdecls.append("\tdbus_int32_t *%s;" % name)
            self.ccode.append("\tlist = %s;" % self.call)
            self.ccode.append("\t%s = purple_dbusify_%s(list, FALSE, &%s_LEN);" % \
                         (name, type[0], name))
            if (not (self.function.name in constlists)):
                self.ccode.append("\tg_%s_free(list);" % type[0].lower()[1:])
            self.cparamsout.append("DBUS_TYPE_ARRAY, DBUS_TYPE_INT32, &%s, %s_LEN" \
                              % (name, name))
            self.addouttype("ai", name)

    # Special case for *_get_data functions
    def inputgetdata(self, type, name):
        self.cdecls.append("\tsize_t %s = 0;" % name)
        return True
    def outputgetdata(self, type, name):
        # This is a total hack, but self.call is set up before the parameters
        #  are processed, so we can't tell it to pass a parameter by reference.
        self.call = "%s(%s)" % (self.function.name,
                                ", ".join([(param.name, "&len")[param.name == "len"] for param in self.params]))

        self.cdecls.append("\tgconstpointer %s;" % name)
        self.ccode.append("\t%s = %s;" % (name, self.call))
        self.cparamsout.append("DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &%s, %s" \
                               % (name, "len"))
        self.addouttype("ay", name)

class BindingSet:
    regexp = r"^(\w[^()]*)\(([^()]*)\)\s*;\s*$";

    def __init__(self, inputfile, fprefix):
        self.inputiter = iter(inputfile)
        self.functionregexp = \
             re.compile("^%s(\w[^()]*)\(([^()]*)\)\s*;\s*$" % fprefix)    
        self.typeregexp = re.compile("^\w+\s*\*?\s*$")


                
    def process(self):
        print("/* Generated by %s.  Do not edit! */" % sys.argv[0])

        for line in self.inputiter:
            words = line.split()
            if len(words) == 0:             # empty line
                continue
            if line[0] == "#":              # preprocessor directive
                continue
            if words[0] in ["typedef", "struct", "enum", "static"]:
                continue

            # accumulate lines until the parentheses are balance or an
            # empty line has been encountered
            myline = line.strip()
            while (myline.count("(") > myline.count(")")) or self.typeregexp.match(myline):
                newline = next(self.inputiter).strip()
                if len(newline) == 0:
                    break
                myline += " " + newline

            # is this a function declaration?
            thematch = self.functionregexp.match(
                myline.replace("*", " " + pointer + " "))

            if thematch is None:
                continue

            functiontext = thematch.group(1)
            paramstext = thematch.group(2).strip()

            if (paramstext == "void") or (paramstext == ""):
                paramtexts = []
            else:
                paramtexts = paramstext.split(",")

            try:
                self.processfunction(functiontext, paramtexts)
            except MyException:
#                sys.stderr.write(myline + "\n")
                 pass
            except:
#                sys.stderr.write(myline + "\n")
                raise

        self.flush()

class ServerBindingSet (BindingSet):
    def __init__(self, inputfile, fprefix):
        BindingSet.__init__(self, inputfile, fprefix)
        self.functions = []


    def processfunction(self, functiontext, paramtexts):
        binding = ServerBinding(functiontext, paramtexts)
        binding.process()
        self.functions.append((binding.function.name, binding.dparams))
        
    def flush(self):
        print("static PurpleDBusBinding bindings_DBUS[] = { ")
        for function, params in self.functions:
            print('{"%s", "%s", %s_DBUS},' % \
                  (ctopascal(function), params, function))

        print("{NULL, NULL, NULL}")
        print("};")

        print("#define PURPLE_DBUS_REGISTER_BINDINGS(handle) purple_dbus_register_bindings(handle, bindings_DBUS)")
        
class ClientBindingSet (BindingSet):
    def __init__(self, inputfile, fprefix, headersonly):
        BindingSet.__init__(self, inputfile, fprefix)
        self.functions = []
        self.knowntypes = []
        self.headersonly = headersonly

    def processfunction(self, functiontext, paramtexts):
        binding = ClientBinding(functiontext, paramtexts, self.knowntypes, self.headersonly)
        binding.process()

    def flush(self):
        pass

# Main program

options = {}

for arg in sys.argv[1:]:
    if arg[0:2] == "--":
        mylist = arg[2:].split("=",1)
        command = mylist[0]
        if len(mylist) > 1:
            options[command] = mylist[1]
        else:
            options[command] = None

if "export-only" in options:
    fprefix = "DBUS_EXPORT\s+"
else:
    fprefix = ""

#sys.stderr.write("%s: Functions not exported:\n" % sys.argv[0])

if "client" in options:
    bindings = ClientBindingSet(sys.stdin, fprefix,
                                "headers" in options)
else:
    bindings = ServerBindingSet(sys.stdin, fprefix)
bindings.process()




