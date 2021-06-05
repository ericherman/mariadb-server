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



static void *json_temp_malloc(size_t size)
{
  return my_malloc(PSI_NOT_INSTRUMENTED, size, MYF(MY_THREAD_SPECIFIC|MY_WME));
}

int json_temp_object_init(struct json_temp_object *obj)
{
  uint init_alloc= 20;
  uint alloc_increment= 20;
  size_t element_size= sizeof(struct json_temp_kv);
  return my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &obj->kv_pairs,
         element_size, init_alloc, alloc_increment,
         MYF(MY_THREAD_SPECIFIC|MY_WME));
}

int json_temp_array_init(struct json_temp_array *array)
{
  uint init_alloc= 20;
  uint alloc_increment= 20;
  size_t element_size= sizeof(struct json_temp_value);
  return my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &array->values,
           element_size, init_alloc, alloc_increment,
           MYF(MY_THREAD_SPECIFIC|MY_WME));
}

int json_temp_string_init(struct json_temp_string *string,
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

void json_temp_string_free(struct json_temp_string *string)
{
  my_free(string->buf);
  string->buf= NULL;
  string->buf_size= 0;
}

static int
json_temp_object_append_key_value(struct json_temp_object *obj,
                                  char *key, size_t key_len,
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


static void
json_temp_value_free(struct json_temp_value *value)
{
	DBUG_ASSERT(value->type != JSON_VALUE_UNINITIALIZED);
  switch (value->type) {
  case JSON_VALUE_STRING:
    json_temp_string_free(&value->value.string);
    break;
  case JSON_VALUE_OBJECT:
    DBUG_ASSERT(0);
    break;
  case JSON_VALUE_ARRAY:
    DBUG_ASSERT(0);
    break;
  default:
    break;
  }
}


static int json_temp_kv_comp(const struct json_temp_kv *a,
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
      struct json_temp_kv *kv= dynamic_element(pairs, 0, struct json_temp_kv*);
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
      value= dynamic_element(values, 0, struct json_temp_value*);
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
json_temp_free(struct json_temp_value *v)
{
  switch (v->type) {
  case JSON_VALUE_OBJECT:
  {
    size_t i;
    struct json_temp_object *obj= &v->value.object;

    DYNAMIC_ARRAY *pairs_arr= &obj->kv_pairs;
    for (i= 0; i < pairs_arr->elements; ++i)
    {
      struct json_temp_kv *kv= dynamic_element(pairs_arr, i, struct json_temp_kv *);
      json_temp_string_free(&kv->key);
      json_temp_free(&kv->value);
    }
    delete_dynamic(pairs_arr);
    break;
  }
  case JSON_VALUE_ARRAY:
  {
    size_t i;
    struct json_temp_array *arr= &v->value.array;

    DYNAMIC_ARRAY *values_arr= &arr->values;
    for (i= 0; i < arr->values.elements; ++i)
    {
      struct json_temp_value *jt_value= ((struct json_temp_value *) values_arr->buffer) + i;
      json_temp_free(jt_value);
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
  {
    DBUG_ASSERT(0);
    break;
  }
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  {
    break;
  }
  case JSON_VALUE_UNINITIALIZED:
    DBUG_ASSERT(0);
    break;
  }
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
    DBUG_ASSERT(0);
    break;
  }
  case JSON_VALUE_UNINITIALIZED:
  {
    DBUG_ASSERT(0);
    break;
  }
  }
  return buf;
}

static int
json_temp_store_current_value(struct json_temp_value *current,
                              json_engine_t *je)
{
  if (json_value_scalar(je))
  {
    /* TODO fix in tests. Assume this is for ARRAYS */
    current->type= je->value_type;
    switch (current->type)
    {
    case JSON_VALUE_STRING:
    {
      const char *je_value_begin= (const char *)je->value_begin;
      size_t je_value_len= (je->value_end - je->value_begin);
      return json_temp_value_type_string_init(current,
                                              je_value_begin,
                                              je_value_len);
    }
    case JSON_VALUE_NUMBER:
    {
      DBUG_ASSERT(0);
      return 1;
    }
    default: /* No value to be set for other types. */
      return 0;
    }
  }
  else
  {
    if (je->value_type == JSON_VALUE_OBJECT)
    {
      current->type= JSON_VALUE_OBJECT;
      return json_temp_object_init(&current->value.object);
    }
    else
    {
      DBUG_ASSERT(je->value_type == JSON_VALUE_ARRAY);
      current->type= JSON_VALUE_ARRAY;
      return json_temp_array_init(&current->value.array);
    }
  }
}

static int
json_temp_append_to_array(struct json_temp_value *current,
                          json_engine_t *je)
{
  DBUG_ASSERT(current->type == JSON_VALUE_ARRAY);
  DBUG_ASSERT(je->value_type != JSON_VALUE_UNINITIALIZED);
  switch (je->value_type) {
  case JSON_VALUE_STRING:
  {
    size_t je_value_len= (je->value_end - je->value_begin);
    struct json_temp_value tmp;
    int err;
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
  case JSON_VALUE_OBJECT:
  case JSON_VALUE_ARRAY:
  case JSON_VALUE_NUMBER:
    DBUG_ASSERT(0);
    return 1;

  default:
    DBUG_ASSERT(0);
    return 1;
  }
}

int json_normalize(char *buf, size_t buf_size, const uchar *s, size_t size,
                   CHARSET_INFO *cs)
{
  json_engine_t je;
  int err= 0;
  const size_t key_buf_size= 100;
  char key_buf[100]; /* TODO */
  size_t key_len= 0;
  struct json_temp_value stack[JSON_DEPTH_LIMIT];
  struct json_temp_value *root = stack;
  struct json_temp_value *current = stack;


  DBUG_ASSERT(buf);
  DBUG_ASSERT(buf_size);
  DBUG_ASSERT(s);

  buf[0]= '\0';
  memset(key_buf, 0x00, key_buf_size);
  memset(&je, 0x00, sizeof(je));
  memset(stack, 0x00, sizeof(stack)) ;

  err= json_scan_start(&je, cs, s, s + size);

  /* json_temp_malloc(DEFAULT_NUM_KEYS * sizeof(struct json_temp_string)); */

  /* first figure out the root */

  do {
    switch (je.state)
    {
    case JST_KEY:
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
      if (json_value_scalar(&je))
      {
        size_t je_value_len= (je.value_end - je.value_begin);
        struct json_temp_value jt_value;
        /* TODO: differences between true/false/string. */
        /* TODO: FIXXXME: switch (je.value_type) { */
        /* case (JSON_VALUE_STRING) { */
        if (json_temp_value_type_string_init(&jt_value, (const char *)je.value_begin,
                                             je_value_len))
          goto json_normalize_error;

        if (json_temp_object_append_key_value(&current->value.object,
                                              key_buf, key_len, &jt_value))
        {
          json_temp_string_free(&jt_value.value.string);
          goto json_normalize_error;
        }
      }
      else
      {
        struct json_temp_value *next = current + 1;
        DBUG_ASSERT(je.value_type == JSON_VALUE_ARRAY ||
                    je.value_type == JSON_VALUE_OBJECT);
        next->type= je.value_type;
        if (next->type == JSON_VALUE_OBJECT) {
          struct json_temp_value obj;
          obj.type = JSON_VALUE_OBJECT;
          json_temp_object_init(&obj.value.object);
          if (json_temp_object_append_key_value(&current->value.object,
                                                key_buf, key_len, &obj))
          {
            /* TODO don't leak */
            goto json_normalize_error;
          }
        }


        DBUG_ASSERT(0);
        /* Need to handle arrays / objects recursively? */
      }


      break;
    case JST_VALUE:
      if (json_read_value(&je))
        goto json_normalize_error;
      // This was initially for 'root' (base object)
      if (current->type == JSON_VALUE_UNINITIALIZED)
      {
        // TODO error handling
        json_temp_store_current_value(current, &je);
        break;
      }
      if (json_value_scalar(&je))
      {
        // TODO error handling
        json_temp_append_to_array(current, &je);
        break;
      }

      if (je.value_type == JSON_VALUE_OBJECT)
      {
        current->type= JSON_VALUE_OBJECT;
        json_temp_object_init(&current->value.object);
      }
      else
      {
        DBUG_ASSERT(0);
      }


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
      break;
    case JST_ARRAY_START:
      /* parser found an array (the '[' in JSON) */
      break;
    case JST_ARRAY_END:
      /* TODO: this needs to pop off the stack, as does JST_OBJ_END. */
      /* parser found the end of the array (the ']' in JSON) */
      break;
    };
  } while (json_scan_next(&je) == 0);

  json_temp_normalize_sort(root);

  json_temp_to_string(buf, buf_size, root);

  json_temp_free(root);

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


static void test_json_normalize_single_kv(void)
{
  const char *in= ""
  "{\n"
  "  \"foo\": \"value\"\n"
  "}\n";

  const char *expected= "{\"foo\":\"value\"}";
  check_json_normalize(in, expected);
}


static void test_json_normalize_multi_kv(void)
{
  const char *in= ""
  "{\n"
  "  \"bar\": \"baz\",\n"
  "  \"foo\": \"value\"\n"
  "}\n";

  const char *expected= "{\"bar\":\"baz\",\"foo\":\"value\"}";
  check_json_normalize(in, expected);
}


static void test_json_normalize_array(void)
{
  const char *in= "[ \"a\", \"b\" ]";
  const char *expected= "[\"a\",\"b\"]";
  check_json_normalize(in, expected);
}


static void test_json_normalize_values(void)
{
  check_json_normalize("\"foo\"", "\"foo\"");
  check_json_normalize("true", "true");
  check_json_normalize("false", "false");
  check_json_normalize("null", "null");
  check_json_normalize("\"\"", "\"\"");
  check_json_normalize("{}", "{}");
  check_json_normalize("[]", "[]");
}

#if 0
static void test_json_normalize_multi_kv(void)
{
  const char *in = ""
  "{\n"
  "  \"foo\": \"value\",\n"
  "  \"wiz\": [true, false, {\n"
  "\t\t\"bang\": \"a\",\n\t\t\"alpha\": false\n\t},\n  \"string\",\n"
  "\t{ \"b\": \"one\", \"a\": \"two\", \"b\": \"three\"}, false,\n"
  "\t\t[\"z\", \"w\", \"x\"]],\n"
  "  \"bar\": \"value2\"\n"
  "}\n";

  const char *expected= "{\"bar\":\"value2\",\"foo\":\"value\"}";
  check_json_normalize(in, expected);
}
#endif

int main(void)
{

  plan(20);
  diag("Testing json_normalization.");

  test_json_normalize_values();
  test_json_normalize_single_kv();
  test_json_normalize_multi_kv();
  test_json_normalize_array();
#if 0
  test_json_normalize_multi_kv();
#endif

  return exit_status();
}
