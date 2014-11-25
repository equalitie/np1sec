using namespace std;

class Base64
{
  static const char b64_table[65];
  static const char reverse_table[128];
 public:
  static string Encode(const string &bindata);
  static string Decode(const char* data, const char* data_end);

};
