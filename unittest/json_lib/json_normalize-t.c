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


struct json_temp_string { /* this covers both keys and values as strings */
  size_t buf_size;
  char *buf;
};


struct json_temp_array {
  /* struct json_temp_value *values; */
  DYNAMIC_ARRAY values;
};


struct json_temp_object {
  /* PAIR(struct json_temp_string, struct json_temp_value) */
  DYNAMIC_ARRAY kv_pairs;
};


struct json_temp_value {
  enum json_value_types type;
  union {
    double number;
    struct json_temp_string string;
    struct json_temp_array array;
    struct json_temp_object object;
  } value;
};


struct json_temp_kv {
  struct json_temp_string key;
  struct json_temp_value  value;
};


static void *
json_temp_malloc(size_t size)
{
  return my_malloc(PSI_NOT_INSTRUMENTED, size, MYF(MY_THREAD_SPECIFIC|MY_WME));
}


int
json_temp_object_init(struct json_temp_object *obj)
{
  uint init_alloc= 20;
  uint alloc_increment= 20;
  size_t element_size= sizeof(struct json_temp_kv);
  return my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &obj->kv_pairs,
         element_size, init_alloc, alloc_increment,
         MYF(MY_THREAD_SPECIFIC|MY_WME));
}


int
json_temp_value_type_array_init(struct json_temp_value *val)
{
  const uint init_alloc= 20;
  const uint alloc_increment= 20;
  const size_t element_size= sizeof(struct json_temp_value);
  struct json_temp_array *array= &val->value.array;
  val->type= JSON_VALUE_ARRAY;
  return my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &array->values,
           element_size, init_alloc, alloc_increment,
           MYF(MY_THREAD_SPECIFIC|MY_WME));
}


int
json_temp_string_init(struct json_temp_string *string,
                      const char *str, size_t len)
{
  string->buf_size= len + 1;
  string->buf= json_temp_malloc(string->buf_size);
  if (!string->buf)
  {
    string->buf_size= 0;
    return 1;
  }
  strncpy((char *)string->buf, str, len);
  string->buf[len]= 0;
  return 0;
}


void
json_temp_string_free(struct json_temp_string *string)
{
  my_free(string->buf);
  string->buf= NULL;
  string->buf_size= 0;
}


static int
json_temp_object_append_key_value(struct json_temp_object *obj,
                                  const char *key, size_t key_len,
                                  struct json_temp_value *v)
{
  struct json_temp_kv pair;
  int err= json_temp_string_init(&pair.key, key, key_len);

  if (err)
    return 1;

  pair.value= *v;

  err|= insert_dynamic(&obj->kv_pairs, &pair);
  if (err)
  {
    json_temp_string_free(&pair.key);
    return 1;
  }

  return 0;
}


static struct json_temp_kv*
json_temp_object_get_last_element(struct json_temp_object *obj)
{
  struct json_temp_kv *kv;

  DBUG_ASSERT(obj->kv_pairs.elements > 0);
  kv= dynamic_element(&obj->kv_pairs,
                      obj->kv_pairs.elements - 1,
                      struct json_temp_kv*);
  return kv;
}


static struct json_temp_value*
json_temp_array_get_last_element(struct json_temp_array *arr)
{
  struct json_temp_value *value;

  DBUG_ASSERT(arr->values.elements > 0);
  value= dynamic_element(&arr->values,
                         arr->values.elements - 1,
                         struct json_temp_value*);
  return value;
}


static int
json_temp_array_append_value(struct json_temp_array *arr,
                             struct json_temp_value *v)
{
  return insert_dynamic(&arr->values, v);
}


static int
json_temp_value_type_string_init(struct json_temp_value *ret,
                                 const char *str, size_t len)
{
  ret->type= JSON_VALUE_STRING;
  return json_temp_string_init(&ret->value.string, str, len);
}


static int
json_temp_kv_comp(const struct json_temp_kv *a,
                  const struct json_temp_kv *b)
{
  return strcmp(a->key.buf, b->key.buf);
}


static void
json_temp_normalize_sort(struct json_temp_value *v)
{
  switch (v->type) {
  case JSON_VALUE_OBJECT:
  {
    size_t i;
    DYNAMIC_ARRAY *pairs= &v->value.object.kv_pairs;
    for (i= 0; i < pairs->elements; ++i)
    {
      struct json_temp_kv *kv= dynamic_element(pairs, i, struct json_temp_kv*);
      json_temp_normalize_sort(&kv->value);
    }

    my_qsort((uchar*) dynamic_element(pairs, 0, struct json_temp_kv*),
        pairs->elements, sizeof(struct json_temp_kv),
        (qsort_cmp) json_temp_kv_comp);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    /* Arrays in JSON must keep the order. Just recursively sort values. */
    size_t i;
    DYNAMIC_ARRAY *values= &v->value.array.values;
    for (i= 0; i < values->elements; ++i)
    {
      struct json_temp_value *value;
      value= dynamic_element(values, i, struct json_temp_value*);
      json_temp_normalize_sort(value);
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
json_temp_value_free(struct json_temp_value *v)
{
  size_t i;
  switch (v->type) {
  case JSON_VALUE_OBJECT:
  {
    struct json_temp_object *obj= &v->value.object;

    DYNAMIC_ARRAY *pairs_arr= &obj->kv_pairs;
    for (i= 0; i < pairs_arr->elements; ++i)
    {
      struct json_temp_kv *kv;
      kv= dynamic_element(pairs_arr, i, struct json_temp_kv *);
      json_temp_string_free(&kv->key);
      json_temp_value_free(&kv->value);
    }
    delete_dynamic(pairs_arr);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    struct json_temp_array *arr= &v->value.array;

    DYNAMIC_ARRAY *values_arr= &arr->values;
    for (i= 0; i < arr->values.elements; ++i)
    {
      struct json_temp_value *jt_value;
      jt_value= dynamic_element(values_arr, i, struct json_temp_value *);
      json_temp_value_free(jt_value);
    }
    delete_dynamic(values_arr);
    break;
  }
  case JSON_VALUE_STRING:
  {
    json_temp_string_free(&v->value.string);
    break;
  }
  case JSON_VALUE_NUMBER:
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  case JSON_VALUE_UNINITIALIZED:
    break;
  }
  v->type= JSON_VALUE_UNINITIALIZED;
}


static char *
json_temp_to_string(char *buf, size_t size, struct json_temp_value *v)
{
  DBUG_ASSERT(buf);
  DBUG_ASSERT(size);
  memset(buf, 0x00, size);

  switch (v->type)
  {
  case JSON_VALUE_OBJECT:
  {
    size_t i, used_buf_len;
    struct json_temp_object *obj= &v->value.object;
    DYNAMIC_ARRAY *pairs_arr= &obj->kv_pairs;

    strcat(buf, "{");

    for (i= 0; i < pairs_arr->elements; ++i)
    {
      struct json_temp_kv *kv;
      kv= dynamic_element(pairs_arr, i, struct json_temp_kv *);

      strcat(buf, "\"");
      strcat(buf, kv->key.buf);
      strcat(buf, "\":");
      used_buf_len= strlen(buf);
      /* TODO: watch out for buffer overflow. */
      json_temp_to_string(buf + used_buf_len, size - used_buf_len, &kv->value);
      if (i != (pairs_arr->elements - 1))
       strcat(buf, ",");
    }
    strcat(buf, "}");
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    size_t i, used_buf_len;
    struct json_temp_array *arr= &v->value.array;
    DYNAMIC_ARRAY *values_arr= &arr->values;

    strcat(buf, "[");
    for (i= 0; i < values_arr->elements; ++i) {
      struct json_temp_value *jt_value;
      jt_value= dynamic_element(values_arr, i, struct json_temp_value *);

      used_buf_len= strlen(buf);
      json_temp_to_string(buf + used_buf_len, size - used_buf_len, jt_value);
      if (i != (values_arr->elements - 1))
       strcat(buf, ",");
    }
    strcat(buf, "]");
    break;
  }
  case JSON_VALUE_STRING:
  {
    strcat(buf, (const char *)v->value.string.buf);
    break;
  }
  case JSON_VALUE_NULL:
  {
    strcat(buf, "null");
    break;
  }
  case JSON_VALUE_TRUE:
  {
    strcat(buf, "true");
    break;
  }
  case JSON_VALUE_FALSE:
  {
    strcat(buf, "false");
    break;
  }
  case JSON_VALUE_NUMBER:
  {
    double d= v->value.number;
    my_bool err= 0;
    char dbuf[DTOA_BUFF_SIZE];
    size_t width= DTOA_BUFF_SIZE-1;
    size_t len= my_gcvt(d, MY_GCVT_ARG_DOUBLE, width, dbuf, &err);
    (void)len;
    if (err) {
      /* TODO: handle err */
      DBUG_ASSERT(0);
    }
    /* TODO: handle all the buffer overflow cases */
    strcat(buf, dbuf);
    break;
  }
  case JSON_VALUE_UNINITIALIZED:
  {
    DBUG_ASSERT(0);
    break;
  }
  }
  /* TODO: handle all the buffer overflow cases */
  return buf;
}


static int
json_temp_get_number_value(struct json_temp_value *current,
                           json_engine_t *je)
{
  int err= 0;
  const char *begin= (const char *)je->value_begin;
  char *end= (char *)je->value_end;
  double d= my_strtod(begin, &end, &err);
  DBUG_ASSERT(d == d); /* NaN is not valid JSON */
  /* https://datatracker.ietf.org/doc/html/rfc8259#section-6 */
  if (err)
    return 1;
  current->value.number= d;
  return 0;
}


static int
json_temp_append_to_array(struct json_temp_value *current,
                          json_engine_t *je)
{
  int err;
  struct json_temp_value tmp;

  DBUG_ASSERT(current->type == JSON_VALUE_ARRAY);
  DBUG_ASSERT(je->value_type != JSON_VALUE_UNINITIALIZED);

  switch (je->value_type) {
  case JSON_VALUE_STRING:
  {
    size_t je_value_len= (je->value_end - je->value_begin);
    err= json_temp_value_type_string_init(&tmp,
                                          (const char *)je->value_begin,
                                          je_value_len);
    if (err)
      return err;
    err= json_temp_array_append_value(&current->value.array, &tmp);
    if (err)
       json_temp_value_free(&tmp);
    return err;
  }
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  {
    tmp.type= je->value_type;
    return json_temp_array_append_value(&current->value.array, &tmp);
  }

  case JSON_VALUE_ARRAY:
  {
    // TODO:Have a json_temp_value_type_xxxx_init for all types.
    err= json_temp_value_type_array_init(&tmp);
    if (err)
      return err;
    err= json_temp_array_append_value(&current->value.array, &tmp);
    if (err)
      json_temp_value_free(&tmp);
    return err;
  }
  case JSON_VALUE_OBJECT:
  {
    tmp.type= je->value_type;
    err= json_temp_object_init(&tmp.value.object);
    if (err)
      return err;
    err= json_temp_array_append_value(&current->value.array, &tmp);
    // TODO: remove some of this duplication
    if (err)
      json_temp_value_free(&tmp);
    return err;
  }
  case JSON_VALUE_NUMBER:
    tmp.type= je->value_type;
    err= json_temp_get_number_value(&tmp, je);
    if (err)
      return err;
    err= json_temp_array_append_value(&current->value.array, &tmp);
    // TODO: remove some of this duplication
    if (err)
      json_temp_value_free(&tmp);
    return err;

  default:
    DBUG_ASSERT(0);
    return 1;
  }
}


static int
json_temp_append_to_object(struct json_temp_value *current,
                           const char *key_buf, size_t key_len,
                           json_engine_t *je)
{
  int err= 0;
  struct json_temp_value tmp;

  DBUG_ASSERT(current->type == JSON_VALUE_OBJECT);
  DBUG_ASSERT(je->value_type != JSON_VALUE_UNINITIALIZED);

  switch (je->value_type) {
  case JSON_VALUE_STRING:
  {
    size_t je_value_len= (je->value_end - je->value_begin);
    err= json_temp_value_type_string_init(&tmp,
                                          (const char *)je->value_begin,
                                          je_value_len);
    break;
  }
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  {
    tmp.type= je->value_type;
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    err= json_temp_value_type_array_init(&tmp);
    break;
  }
  case JSON_VALUE_OBJECT:
  {
    // TODO:Have a json_temp_value_type_xxxx_init for all types.
    tmp.type= je->value_type;
    err= json_temp_object_init(&tmp.value.object);
    break;
  }
  case JSON_VALUE_NUMBER:
    tmp.type= je->value_type;
    err= json_temp_get_number_value(&tmp, je);
    break;
  default:
    DBUG_ASSERT(0);
    return 1;
  }

  if (err)
    return 1;
  err= json_temp_object_append_key_value(&current->value.object, key_buf,
                                         key_len, &tmp);
  if (err)
    json_temp_value_free(&tmp);

  return err;
}


int
json_normalize(char *buf, size_t buf_size, const uchar *s, size_t size,
               CHARSET_INFO *cs)
{
  json_engine_t je;
  int err= 0;
  const size_t key_buf_size= 100;
  char key_buf[100]; /* TODO */
  size_t key_len= 0;
  size_t current;
  struct json_temp_value *stack[JSON_DEPTH_LIMIT];
  struct json_temp_value root;


  DBUG_ASSERT(buf);
  DBUG_ASSERT(buf_size);
  DBUG_ASSERT(s);

  buf[0]= '\0';
  memset(key_buf, 0x00, key_buf_size);
  memset(&je, 0x00, sizeof(je));
  memset(stack, 0x00, sizeof(stack));
  memset(&root, 0x00, sizeof(root));

  root.type= JSON_VALUE_UNINITIALIZED;
  current= 0;
  stack[current]= &root;

  err= json_scan_start(&je, cs, s, s + size);
  if (json_read_value(&je))
    goto json_normalize_error;

  // TODO: this will not be necessary once we have all init functions
  root.type = je.value_type;
  switch (root.type) {
  case JSON_VALUE_OBJECT:
    err= json_temp_object_init(&root.value.object);
    if (err)
      goto json_normalize_error; // TODO cleanup
    break;
  case JSON_VALUE_ARRAY:
    err= json_temp_value_type_array_init(&root);
    if (err)
      goto json_normalize_error; // TODO cleanup
    break;
  case JSON_VALUE_STRING:
  {
    const char *je_value_begin= (const char *)je.value_begin;
    size_t je_value_len= (je.value_end - je.value_begin);
    if (json_temp_value_type_string_init(&root, je_value_begin, je_value_len))
      goto json_normalize_error;
    goto json_normalize_print_and_free;
  }
  case JSON_VALUE_NUMBER:
  {
    if (json_temp_get_number_value(&root, &je))
      goto json_normalize_error;
    goto json_normalize_print_and_free;
  }
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  case JSON_VALUE_NULL:
    goto json_normalize_print_and_free;
  default:
    DBUG_ASSERT(0);
  }


  /* Restart the scan now that we know the type of the root element. */
  /*memset(&je, 0x00, sizeof(je));
  err= json_scan_start(&je, cs, s, s + size);
  */
  /* json_temp_malloc(DEFAULT_NUM_KEYS * sizeof(struct json_temp_string)); */

  /* first figure out the root */

  do {
    switch (je.state)
    {
    case JST_KEY:
      DBUG_ASSERT(stack[current]->type == JSON_VALUE_OBJECT);
      /* we have the key name */
      /* json_read_keyname_chr() */
      key_len= 0;
      while (json_read_keyname_chr(&je) == 0)
      {
        key_buf[key_len++]= je.s.c_next;
      }
      key_buf[key_len]= '\0';

      /* After reading the key, we have a follow-up value. */
      if (json_read_value(&je))
        goto json_normalize_error;

      // TODO: idea: Write code such that switch from below works regardless
      // of depth level.
      if (json_temp_append_to_object(stack[current], key_buf, key_len, &je))
        goto json_normalize_error;
      if (!json_value_scalar(&je))
      {
        struct json_temp_kv *kv;
        /* TODO: Evaluate if checking for stack overflow is necessary,
           json_engine should already cover it. */
        DBUG_ASSERT(je.value_type == JSON_VALUE_ARRAY ||
                    je.value_type == JSON_VALUE_OBJECT);
        kv= json_temp_object_get_last_element(&stack[current]->value.object);
        stack[current + 1]= &kv->value;
        current+= 1;
      }
      break;
    case JST_VALUE:
      if (json_read_value(&je))
        goto json_normalize_error;
      if (json_value_scalar(&je))
      {
        // TODO error handling
        json_temp_append_to_array(stack[current], &je);
        break;
      }

      DBUG_ASSERT(stack[current]->type == JSON_VALUE_ARRAY);
      DBUG_ASSERT(je.value_type == JSON_VALUE_ARRAY ||
                  je.value_type == JSON_VALUE_OBJECT);

      json_temp_append_to_array(stack[current], &je);
      {
        // TODO: Change compiler to use C11.
        struct json_temp_array *current_arr= &stack[current]->value.array;
        stack[current + 1]= json_temp_array_get_last_element(current_arr);
      }
      ++current;


      /* see the json_read_value() */
      break;
    case JST_OBJ_START:
       /* parser found an object (the '{' in JSON) */
      /* time to recurse! */
      break;
    case JST_OBJ_END:
      /* TODO: this looks like a bug in the parser, it never reaches. */
      /* parser found the end of the object (the '}' in JSON) */
      /* pop recursion */
      --current;
      break;
    case JST_ARRAY_START:
      /* parser found an array (the '[' in JSON) */
      break;
    case JST_ARRAY_END:
      /* TODO: this needs to pop off the stack, as does JST_OBJ_END. */
      /* parser found the end of the array (the ']' in JSON) */
      --current;
      break;
    };
  } while (json_scan_next(&je) == 0);

  json_temp_normalize_sort(&root);

json_normalize_print_and_free:
  json_temp_to_string(buf, buf_size, &root);

  json_temp_value_free(&root);

  return err;

json_normalize_error:
  DBUG_ASSERT(0);
  return 1; /* TODO don't leak. */
}


static void
check_json_normalize(const char *in, const char *expected)
{
  const size_t actual_size= 1024;
  char actual[1024]; /* C89 */

  const size_t msg_size= 1024;
  char msg[1024]; /* C89 */

  CHARSET_INFO *cs= &my_charset_utf8mb4_general_ci;

  int err= json_normalize(actual, actual_size, (const uchar *)in, strlen(in), cs);

  ok(err == 0, "normalize err?");

  snprintf(msg, msg_size, "expected '%s' from '%s' but was '%s'", expected, in, actual);
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
