/* Copyright (c) 2021 Eric Herman and MariaDB Foundation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#include "my_config.h"
#include "config.h"
#include <tap.h>
#include <my_global.h>
#include <my_sys.h> /* my_malloc */
#include <m_ctype.h> /* TODO: this should be in json_lib.h */
#include <json_lib.h>


static void
check_json_normalize(const char *in, const char *expected)
{
  int err;
  DYNAMIC_STRING result;

  const size_t msg_size= 1024;
  char msg[1024]; /* C89 */

  CHARSET_INFO *cs= &my_charset_utf8mb4_general_ci;

  init_dynamic_string(&result, NULL, 0, 0);

  err= json_normalize(&result, in, strlen(in), cs);

  ok(err == 0, "normalize err?");

  snprintf(msg, msg_size,
           "expected '%s' from '%s' but was '%s'",
           expected, in, result.str);

  ok(strcmp(expected, result.str) == 0, msg);

  dynstr_free(&result);
}


static void
test_json_normalize_invalid(void)
{
  DYNAMIC_STRING result;

  CHARSET_INFO *cs= &my_charset_utf8mb4_general_ci;

  init_dynamic_string(&result, NULL, 0, 0);
  ok(json_normalize(&result, STRING_WITH_LEN(""), cs) != 0,
     "expected normalized error");
  dynstr_free(&result);

  init_dynamic_string(&result, NULL, 0, 0);
  ok(json_normalize(&result, STRING_WITH_LEN("["), cs) != 0,
     "expected normalized error");
  dynstr_free(&result);

  init_dynamic_string(&result, NULL, 0, 0);
  ok(json_normalize(&result, STRING_WITH_LEN("}"), cs) != 0,
     "expected normalized error");
  dynstr_free(&result);

  init_dynamic_string(&result, NULL, 0, 0);
  ok(json_normalize(&result, NULL, 0, cs) != 0,
     "expected normalized error");
  dynstr_free(&result);
}


static void
test_json_normalize_single_kv(void)
{
  const char *in= ""
  "{\n"
  "  \"foo\": \"value\"\n"
  "}\n";

  const char *expected= "{\"foo\":\"value\"}";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_multi_kv(void)
{
  const char *in= ""
  "{\n"
  "  \"bar\": \"baz\",\n"
  "  \"foo\": \"value\"\n"
  "}\n";

  const char *expected= "{\"bar\":\"baz\",\"foo\":\"value\"}";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_array(void)
{
  const char *in= "[ \"a\", \"b\", true, false, null ]";
  const char *expected= "[\"a\",\"b\",true,false,null]";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_values(void)
{
  check_json_normalize("\"foo\"", "\"foo\"");
  check_json_normalize("true", "true");
  check_json_normalize("false", "false");
  check_json_normalize("null", "null");
  check_json_normalize("\"\"", "\"\"");
  check_json_normalize("{}", "{}");
  check_json_normalize("[]", "[]");
  check_json_normalize("5", "5");
  check_json_normalize("5.1", "5.1");
  check_json_normalize("-5.1", "-5.1");
  check_json_normalize("12345.67890", "12345.6789");
  check_json_normalize("2.99792458e8", "299792458");
  check_json_normalize("6.02214076e23", "6.02214076e23");
  check_json_normalize("6.62607015e-34", "6.62607015e-34");
  check_json_normalize("-6.62607015e-34", "-6.62607015e-34");
}


static void
test_json_normalize_nested_objects(void)
{
  const char *in = ""
  "{\n"
  "  \"wiz\": {\n"
  "\t\t\"bang\": \"a\",\n\t\t\"alpha\": false\n\t},\n"
  "  \"foo\": {\"value\":true}\n"
  "}";

  const char *expected= "{\"foo\":{\"value\":true},"
                        "\"wiz\":{\"alpha\":false,\"bang\":\"a\"}}";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_nested_arrays(void)
{
  const char *in = ""
  "[\n"
  "  \"wiz\",\n"
  " [\"bang\", \t\t\"alpha\"\t]\n"
  "]";

  const char *expected= "[\"wiz\",[\"bang\",\"alpha\"]]";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_nested_deep(void)
{
  const char *in = ""
  "{\n"
  "  \"foo\": \"value\",\n"
  "  \"wiz\": [true, false, {\n"
  "\t\t\"bang\": \"a\",\n\t\t\"alpha\": 12345.67890\n\t},\n  \"string\",\n"
  "\t{ \"b\": \"one\", \"a\": \"two\", \"c\": \"three\"}, false,\n"
  "\t\t[-1.20, \"w\", \"x\"]],\n"
  "  \"bar\": \"value2\"\n"
  "}\n";

  const char *expected= ""
  "{"
    "\"bar\":\"value2\","
    "\"foo\":\"value\","
    "\"wiz\":["
               "true,false,"
               "{\"alpha\":12345.6789,\"bang\":\"a\"},"
               "\"string\","
               "{\"a\":\"two\",\"b\":\"one\",\"c\":\"three\"},"
               "false,"
               "[-1.2,\"w\",\"x\"]"
            "]"
  "}";
  check_json_normalize(in, expected);
}


static void
test_json_normalize_non_utf8(void)
{
  int err;
  const char utf8[]= { 0x22, 0xC3, 0x8A, 0x22, 0x00 };
  const char latin[] = { 0x22, 0xCA, 0x22, 0x00 };
  DYNAMIC_STRING result;
  CHARSET_INFO *cs_utf8= &my_charset_utf8mb4_bin;
  CHARSET_INFO *cs_latin= &my_charset_latin1;

  init_dynamic_string(&result, NULL, 0, 0);
  err= json_normalize(&result, utf8, strlen(utf8), cs_utf8);
  ok(err == 0, "normalize err?");
  ok((strcmp(utf8, result.str) == 0), "utf8 round trip");
  dynstr_free(&result);

  init_dynamic_string(&result, NULL, 0, 0);
  err= json_normalize(&result, latin, strlen(latin), cs_latin);
  ok(err == 0, "normalize err?");
  ok((strcmp(utf8, result.str) == 0), "latin to utf8 round trip");
  dynstr_free(&result);
}


int
main(void)
{

  plan(50);
  diag("Testing json_normalization.");

  test_json_normalize_invalid();
  test_json_normalize_values();
  test_json_normalize_single_kv();
  test_json_normalize_multi_kv();
  test_json_normalize_array();
  test_json_normalize_nested_objects();
  test_json_normalize_nested_arrays();
  test_json_normalize_nested_deep();
  test_json_normalize_non_utf8();

  return exit_status();
}
