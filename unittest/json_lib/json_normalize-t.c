/* Copyright (c) 2016, MariaDB Corp. All rights reserved.

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

#ifndef DTOA_BUFF_SIZE
#define DTOA_BUFF_SIZE (460 * sizeof(void *))
#endif

#ifndef PSI_JSON
#define PSI_JSON PSI_NOT_INSTRUMENTED
#endif

/*
From the EXPIRED DRAFT JSON Canonical Form
https://datatracker.ietf.org/doc/html/draft-staykov-hu-json-canonical-form-00

2. JSON canonical form

  The canonical form is defined by the following rules:
  *  The document MUST be encoded in UTF-8 [UTF-8]
  *  Non-significant(1) whitespace characters MUST NOT be used
  *  Non-significant(1) line endings MUST NOT be used
  *  Entries (set of name/value pairs) in JSON objects MUST be sorted
     lexicographically(2) by their names
  *  Arrays MUST preserve their initial ordering

  (1)As defined in JSON data-interchange format [JSON], JSON objects
     consists of multiple "name"/"value" pairs and JSON arrays consists
     of multiple "value" fields. Non-significant means not part of
     "name" or "value".


  (2)Lexicographic comparison, which orders strings from least to
     greatest alphabetically based on the UCS (Unicode Character Set)
     codepoint values.
*/


struct json_norm_array {
  DYNAMIC_ARRAY values;
};


struct json_norm_object {
  DYNAMIC_ARRAY kv_pairs;
};


struct json_norm_value {
  enum json_value_types type;
  union {
    double number;
    LEX_STRING string;
    struct json_norm_array array;
    struct json_norm_object object;
  } value;
};


struct json_norm_kv {
  LEX_STRING key;
  struct json_norm_value  value;
};


static void *
json_norm_malloc(size_t size)
{
  return my_malloc(PSI_JSON, size, MYF(MY_THREAD_SPECIFIC|MY_WME));
}


int
json_norm_string_init(LEX_STRING *string, const char *str, size_t len)
{
  string->length= len + 1;
  string->str= json_norm_malloc(string->length);
  if (!string->str)
  {
    string->length= 0;
    return 1;
  }
  strncpy(string->str, str, len);
  string->str[len]= 0;
  return 0;
}


void
json_norm_string_free(LEX_STRING *string)
{
  my_free(string->str);
  string->str= NULL;
  string->length= 0;
}


static int
json_norm_object_append_key_value(struct json_norm_object *obj,
                                  DYNAMIC_STRING *key,
                                  struct json_norm_value *val)
{
  struct json_norm_kv pair;
  int err= json_norm_string_init(&pair.key, key->str, key->length);

  if (err)
    return 1;

  pair.value= *val;

  err|= insert_dynamic(&obj->kv_pairs, &pair);
  if (err)
  {
    json_norm_string_free(&pair.key);
    return 1;
  }

  return 0;
}


static struct json_norm_kv*
json_norm_object_get_last_element(struct json_norm_object *obj)
{
  struct json_norm_kv *kv;

  DBUG_ASSERT(obj->kv_pairs.elements > 0);
  kv= dynamic_element(&obj->kv_pairs,
                      obj->kv_pairs.elements - 1,
                      struct json_norm_kv*);
  return kv;
}


static struct json_norm_value*
json_norm_array_get_last_element(struct json_norm_array *arr)
{
  struct json_norm_value *val;

  DBUG_ASSERT(arr->values.elements > 0);
  val= dynamic_element(&arr->values,
                       arr->values.elements - 1,
                       struct json_norm_value*);
  return val;
}


static int
json_norm_array_append_value(struct json_norm_array *arr,
                             struct json_norm_value *val)
{
  return insert_dynamic(&arr->values, val);
}


int
json_norm_init_dynmic_array(size_t element_size, void *where)
{
  const uint init_alloc= 20;
  const uint alloc_increment= 20;
  return my_init_dynamic_array(PSI_JSON, where, element_size,
                               init_alloc, alloc_increment,
                               MYF(MY_THREAD_SPECIFIC|MY_WME));
}


int
json_norm_value_object_init(struct json_norm_value *val)
{
  const size_t element_size= sizeof(struct json_norm_kv);
  struct json_norm_object *obj= &val->value.object;

  val->type= JSON_VALUE_OBJECT;

  return json_norm_init_dynmic_array(element_size, &obj->kv_pairs);
}


int
json_norm_value_array_init(struct json_norm_value *val)
{
  const size_t element_size= sizeof(struct json_norm_value);
  struct json_norm_array *array= &val->value.array;

  val->type= JSON_VALUE_ARRAY;

  return json_norm_init_dynmic_array(element_size, &array->values);
}


static int
json_norm_value_string_init(struct json_norm_value *val,
                            const char *str, size_t len)
{
  val->type= JSON_VALUE_STRING;
  return json_norm_string_init(&val->value.string, str, len);
}


static int
json_norm_kv_comp(const struct json_norm_kv *a,
                  const struct json_norm_kv *b)
{
  return strcmp(a->key.str, b->key.str);
}


static void
json_normalize_sort(struct json_norm_value *val)
{
  switch (val->type) {
  case JSON_VALUE_OBJECT:
  {
    size_t i;
    DYNAMIC_ARRAY *pairs= &val->value.object.kv_pairs;
    for (i= 0; i < pairs->elements; ++i)
    {
      struct json_norm_kv *kv= dynamic_element(pairs, i, struct json_norm_kv*);
      json_normalize_sort(&kv->value);
    }

    my_qsort((uchar*) dynamic_element(pairs, 0, struct json_norm_kv*),
        pairs->elements, sizeof(struct json_norm_kv),
        (qsort_cmp) json_norm_kv_comp);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    /* Arrays in JSON must keep the order. Just recursively sort values. */
    size_t i;
    DYNAMIC_ARRAY *values= &val->value.array.values;
    for (i= 0; i < values->elements; ++i)
    {
      struct json_norm_value *value;
      value= dynamic_element(values, i, struct json_norm_value*);
      json_normalize_sort(value);
    }

    break;
  }
  case JSON_VALUE_UNINITIALIZED:
    DBUG_ASSERT(0);
    break;
  default: /* Nothing to do for other types. */
    break;
  }
}


static void
json_norm_value_free(struct json_norm_value *val)
{
  size_t i;
  switch (val->type) {
  case JSON_VALUE_OBJECT:
  {
    struct json_norm_object *obj= &val->value.object;

    DYNAMIC_ARRAY *pairs_arr= &obj->kv_pairs;
    for (i= 0; i < pairs_arr->elements; ++i)
    {
      struct json_norm_kv *kv;
      kv= dynamic_element(pairs_arr, i, struct json_norm_kv *);
      json_norm_string_free(&kv->key);
      json_norm_value_free(&kv->value);
    }
    delete_dynamic(pairs_arr);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    struct json_norm_array *arr= &val->value.array;

    DYNAMIC_ARRAY *values_arr= &arr->values;
    for (i= 0; i < arr->values.elements; ++i)
    {
      struct json_norm_value *jt_value;
      jt_value= dynamic_element(values_arr, i, struct json_norm_value *);
      json_norm_value_free(jt_value);
    }
    delete_dynamic(values_arr);
    break;
  }
  case JSON_VALUE_STRING:
  {
    json_norm_string_free(&val->value.string);
    break;
  }
  case JSON_VALUE_NUMBER:
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  case JSON_VALUE_UNINITIALIZED:
    break;
  }
  val->type= JSON_VALUE_UNINITIALIZED;
}


static int
json_norm_to_dynamic_string(DYNAMIC_STRING *buf, struct json_norm_value *val)
{
  switch (val->type)
  {
  case JSON_VALUE_OBJECT:
  {
    size_t i;
    struct json_norm_object *obj= &val->value.object;
    DYNAMIC_ARRAY *pairs_arr= &obj->kv_pairs;

    if (dynstr_append_mem(buf, STRING_WITH_LEN("{")))
      return 1;

    for (i= 0; i < pairs_arr->elements; ++i)
    {
      struct json_norm_kv *kv;
      kv= dynamic_element(pairs_arr, i, struct json_norm_kv *);

      if (dynstr_append_mem(buf, STRING_WITH_LEN("\"")) ||
          dynstr_append(buf, kv->key.str) ||
          dynstr_append_mem(buf, STRING_WITH_LEN("\":")) ||
          json_norm_to_dynamic_string(buf, &kv->value))
        return 1;

      if (i != (pairs_arr->elements - 1))
        if (dynstr_append_mem(buf, STRING_WITH_LEN(",")))
          return 1;
    }
    if (dynstr_append_mem(buf, STRING_WITH_LEN("}")))
      return 1;
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    size_t i;
    struct json_norm_array *arr= &val->value.array;
    DYNAMIC_ARRAY *values_arr= &arr->values;

    if (dynstr_append_mem(buf, STRING_WITH_LEN("[")))
      return 1;
    for (i= 0; i < values_arr->elements; ++i)
    {
      struct json_norm_value *jt_value;
      jt_value= dynamic_element(values_arr, i, struct json_norm_value *);

      if (json_norm_to_dynamic_string(buf, jt_value))
        return 1;
      if (i != (values_arr->elements - 1))
        if (dynstr_append_mem(buf, STRING_WITH_LEN(",")))
          return 1;
    }
    if (dynstr_append_mem(buf, STRING_WITH_LEN("]")))
      return 1;
    break;
  }
  case JSON_VALUE_STRING:
  {
    if (dynstr_append(buf, val->value.string.str))
      return 1;
    break;
  }
  case JSON_VALUE_NULL:
  {
    if (dynstr_append_mem(buf, STRING_WITH_LEN("null")))
      return 1;
    break;
  }
  case JSON_VALUE_TRUE:
  {
    if (dynstr_append_mem(buf, STRING_WITH_LEN("true")))
      return 1;
    break;
  }
  case JSON_VALUE_FALSE:
  {
    if (dynstr_append_mem(buf, STRING_WITH_LEN("false")))
      return 1;
    break;
  }
  case JSON_VALUE_NUMBER:
  {
    double d= val->value.number;
    char dbuf[DTOA_BUFF_SIZE];
    size_t width= DTOA_BUFF_SIZE-1;
    my_bool err= 0;
    size_t len= my_gcvt(d, MY_GCVT_ARG_DOUBLE, width, dbuf, &err);
    if (err)
      return 1;
    if (dynstr_append_mem(buf, dbuf, len))
      return 1;
    break;
  }
  case JSON_VALUE_UNINITIALIZED:
  {
    DBUG_ASSERT(0);
    break;
  }
  }
  return 0;
}


static char *
json_norm_to_string(char *out, size_t size, struct json_norm_value *val)
{
  DYNAMIC_STRING buf;
  int err;

  DBUG_ASSERT(out);
  DBUG_ASSERT(size);
  memset(out, 0x00, size);

  if (init_dynamic_string(&buf, NULL, 0, 0))
    return NULL;

  err= json_norm_to_dynamic_string(&buf, val);

  if (!err)
    strncpy(out, buf.str, size);

  dynstr_free(&buf);

  return err ? NULL : out;
}


static int
json_norm_get_number_value(double *number, json_engine_t *je)
{
  int err= 0;
  const char *begin= (const char *)je->value_begin;
  char *end= (char *)je->value_end;

  double d= my_strtod(begin, &end, &err);
  if (err)
    return 1;

  /* https://datatracker.ietf.org/doc/html/rfc8259#section-6 */
  DBUG_ASSERT(d == d); /* NaN is not valid JSON */

  *number= d;
  return 0;
}


static void
json_norm_value_number_init(struct json_norm_value *val, double n)
{
  val->type= JSON_VALUE_NUMBER;
  val->value.number= n;
}


static void
json_norm_value_null_init(struct json_norm_value *val)
{
  val->type= JSON_VALUE_NULL;
}


static void
json_norm_value_false_init(struct json_norm_value *val)
{
  val->type= JSON_VALUE_FALSE;
}


static void
json_norm_value_true_init(struct json_norm_value *val)
{
  val->type= JSON_VALUE_TRUE;
}


static int
json_norm_value_init(struct json_norm_value *val, json_engine_t *je)
{
  int err= 0;
  switch (je->value_type) {
  case JSON_VALUE_STRING:
  {
    const char *je_value_begin= (const char *)je->value_begin;
    size_t je_value_len= (je->value_end - je->value_begin);
    err= json_norm_value_string_init(val, je_value_begin, je_value_len);
    break;
  }
  case JSON_VALUE_NULL:
  {
    json_norm_value_null_init(val);
    break;
  }
  case JSON_VALUE_TRUE:
  {
    json_norm_value_true_init(val);
    break;
  }
  case JSON_VALUE_FALSE:
  {
    json_norm_value_false_init(val);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    err= json_norm_value_array_init(val);
    break;
  }
  case JSON_VALUE_OBJECT:
  {
    err= json_norm_value_object_init(val);
    break;
  }
  case JSON_VALUE_NUMBER:
  {
    double number= 0;
    err= json_norm_get_number_value(&number, je);
    json_norm_value_number_init(val, number);
    break;
  }
  default:
    DBUG_ASSERT(0);
    return 1;
  }
  return err;
}


static int
json_norm_append_to_array(struct json_norm_value *val,
                          json_engine_t *je)
{
  int err= 0;
  struct json_norm_value tmp;

  DBUG_ASSERT(val->type == JSON_VALUE_ARRAY);
  DBUG_ASSERT(je->value_type != JSON_VALUE_UNINITIALIZED);

  err= json_norm_value_init(&tmp, je);

  if (err)
    return 1;

  err= json_norm_array_append_value(&val->value.array, &tmp);

  if (err)
    json_norm_value_free(&tmp);

  return err;
}


static int
json_norm_append_to_object(struct json_norm_value *val,
                           DYNAMIC_STRING *key, json_engine_t *je)
{
  int err= 0;
  struct json_norm_value tmp;

  DBUG_ASSERT(val->type == JSON_VALUE_OBJECT);
  DBUG_ASSERT(je->value_type != JSON_VALUE_UNINITIALIZED);

  err= json_norm_value_init(&tmp, je);

  if (err)
    return 1;

  err= json_norm_object_append_key_value(&val->value.object, key, &tmp);

  if (err)
    json_norm_value_free(&tmp);

  return err;
}


static int
json_norm_parse(struct json_norm_value *root, json_engine_t *je)
{
  size_t current;
  struct json_norm_value *stack[JSON_DEPTH_LIMIT];
  int err= 0;
  DYNAMIC_STRING key;

  err= init_dynamic_string(&key, NULL, 0, 0);
  if (err)
    goto json_norm_parse_end;

  memset(stack, 0x00, sizeof(stack));
  current= 0;
  stack[current]= root;

  do {
    switch (je->state)
    {
    case JST_KEY:
    {
      const uchar *key_start= je->s.c_str;
      const uchar *key_end;

      DBUG_ASSERT(stack[current]->type == JSON_VALUE_OBJECT);
      do
      {
        key_end= je->s.c_str;
      } while (json_read_keyname_chr(je) == 0);

      /* we have the key name */
      /* reset the dynstr: */
      dynstr_trunc(&key, key.length);
      dynstr_append_mem(&key, (char *)key_start, (key_end - key_start));

      /* After reading the key, we have a follow-up value. */
      err= json_read_value(je);
      if (err)
        goto json_norm_parse_end;

      err= json_norm_append_to_object(stack[current], &key, je);
      if (err)
        goto json_norm_parse_end;

      if (!json_value_scalar(je))
      {
        struct json_norm_kv *kv;
        DBUG_ASSERT(je->value_type == JSON_VALUE_ARRAY ||
                    je->value_type == JSON_VALUE_OBJECT);
        kv= json_norm_object_get_last_element(&stack[current]->value.object);

        err= ((current + 1) == JSON_DEPTH_LIMIT);
        if (err)
          goto json_norm_parse_end;

        stack[current + 1]= &kv->value;
        current+= 1;
      }
      break;
    }
    case JST_VALUE:
    {
      struct json_norm_array *current_arr= &stack[current]->value.array;
      err= json_read_value(je);
      if (err)
        goto json_norm_parse_end;

      DBUG_ASSERT(stack[current]->type == JSON_VALUE_ARRAY);

      err= json_norm_append_to_array(stack[current], je);
      if (err)
        goto json_norm_parse_end;

      if (je->value_type == JSON_VALUE_ARRAY ||
          je->value_type == JSON_VALUE_OBJECT)
      {

        err= ((current + 1) == JSON_DEPTH_LIMIT);
        if (err)
          goto json_norm_parse_end;

        stack[current + 1]= json_norm_array_get_last_element(current_arr);
        ++current;
      }

      break;
    }
    case JST_OBJ_START:
      /* parser found an object (the '{' in JSON) */
      break;
    case JST_OBJ_END:
      /* parser found the end of the object (the '}' in JSON) */
      /* pop stack */
      --current;
      break;
    case JST_ARRAY_START:
      /* parser found an array (the '[' in JSON) */
      break;
    case JST_ARRAY_END:
      /* parser found the end of the array (the ']' in JSON) */
      /* pop stack */
      --current;
      break;
    };
  } while (json_scan_next(je) == 0);

json_norm_parse_end:
  dynstr_free(&key);
  return err;
}


static int
json_norm_build(struct json_norm_value *root,
                const uchar *s, size_t size, CHARSET_INFO *cs)
{
  int err= 0;
  json_engine_t je;

  DBUG_ASSERT(s);
  memset(&je, 0x00, sizeof(je));

  memset(root, 0x00, sizeof(struct json_norm_value));
  root->type= JSON_VALUE_UNINITIALIZED;

  err= json_scan_start(&je, cs, s, s + size);
  if (json_read_value(&je))
    return err;

  err= json_norm_value_init(root, &je);

  if (root->type == JSON_VALUE_OBJECT ||
      root->type == JSON_VALUE_ARRAY)
  {
    err= json_norm_parse(root, &je);
    if (err)
      return err;
  }
  return err;
}


int
json_normalize(char *buf, size_t buf_size,
               const uchar *s, size_t size, CHARSET_INFO *cs)
{
  int err= 0;
  struct json_norm_value root;
  char *rv;

  DBUG_ASSERT(buf);
  DBUG_ASSERT(buf_size);

  buf[0]= '\0';

  err= json_norm_build(&root, s, size, cs);
  if (err)
    goto json_normalize_end;

  json_normalize_sort(&root);

  rv= json_norm_to_string(buf, buf_size, &root);
  err= rv ? 0 : 1;

json_normalize_end:
  json_norm_value_free(&root);

  return err;
}


static void
check_json_normalize(const char *in, const char *expected)
{
  const size_t actual_size= 1024;
  char actual[1024]; /* C89 */

  const size_t msg_size= 1024;
  char msg[1024]; /* C89 */

  CHARSET_INFO *cs= &my_charset_utf8mb4_general_ci;

  int err= json_normalize(actual, actual_size,
                          (const uchar *)in, strlen(in), cs);

  ok(err == 0, "normalize err?");

  snprintf(msg, msg_size,
           "expected '%s' from '%s' but was '%s'", expected, in, actual);

  ok(strcmp(expected, actual) == 0, msg);
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


int
main(void)
{

  plan(42);
  diag("Testing json_normalization.");

  test_json_normalize_values();
  test_json_normalize_single_kv();
  test_json_normalize_multi_kv();
  test_json_normalize_array();
  test_json_normalize_nested_objects();
  test_json_normalize_nested_arrays();
  test_json_normalize_nested_deep();

  return exit_status();
}
