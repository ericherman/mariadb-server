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

// JSON_OBJECT (array keys, array values)
// JSON ARRAY (array values)
// JSON LITERAL (number, literal (true, false, null), string)


struct json_temp_string { /* this covers both keys and values as strings */
  size_t buf_size;
  uchar *buf;
};

struct json_temp_array {
  /* struct json_temp_value *values; */
  DYNAMIC_ARRAY values;
};

struct json_temp_object {
  /* struct json_temp_string *keys; */
  DYNAMIC_ARRAY keys;
  /* struct json_temp_value  *values; */
  DYNAMIC_ARRAY values;
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


static void *json_temp_malloc(size_t size)
{
  return my_malloc(PSI_NOT_INSTRUMENTED, size, MYF(MY_THREAD_SPECIFIC|MY_WME));
}

int json_temp_object_init(struct json_temp_object *obj)
{
  int err;
  uint init_alloc= 20;
  uint alloc_increment= 20;
  size_t element_size= sizeof(struct json_temp_string);
  err= my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &obj->keys, element_size,
         init_alloc, alloc_increment, MYF(MY_THREAD_SPECIFIC|MY_WME));
  element_size= sizeof(struct json_temp_value);
  err|= my_init_dynamic_array(PSI_NOT_INSTRUMENTED, &obj->values, element_size,
          init_alloc, alloc_increment, MYF(MY_THREAD_SPECIFIC|MY_WME));
  if (err) {
    delete_dynamic(&obj->keys);
    delete_dynamic(&obj->values);
  }
  return err;
}

int json_temp_array_init(struct json_temp_array *array)
{
  uint init_alloc= 20;
  uint alloc_increment= 20;
  size_t element_size= sizeof(struct json_temp_string);
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

static int
json_temp_object_append_key_value(struct json_temp_object *obj, char *key, size_t key_len,
                                  struct json_temp_value *v)
{
  struct json_temp_string json_key_str;
  int err= json_temp_string_init(&json_key_str, key, key_len);
  if (err)
    return err;
  err|= insert_dynamic(&obj->keys, &json_key_str);
  if (err)
  {
    /* TODO: Free json_temp_string. */
    return 1;
  }

  err|= insert_dynamic(&obj->values, v);
  if (err)
  {
    /* TODO: Free json_temp_string. and prev array. */
    return 1;
  }
  return 0;
}


static int
json_temp_value_type_string_init(struct json_temp_value *ret,
                                 const char *str, size_t len)
{
  ret->type= JSON_VALUE_STRING;
  return json_temp_string_init(&ret->value.string, str, len);
}

static void
json_temp_free(struct json_temp_value *v)
{
  switch (v->type) {
  case JSON_VALUE_ARRAY:
  {
    DBUG_ASSERT(0);
    break;
  }
  case JSON_VALUE_OBJECT:
  {
    size_t i;
    struct json_temp_object *obj= &v->value.object;

    DYNAMIC_ARRAY *keys_arr= &obj->keys;
    DYNAMIC_ARRAY *values_arr= &obj->values;
    for (i= 0; i < obj->keys.elements; ++i)
    {
      char *key = (char *)((struct json_temp_string *) keys_arr->buffer)[i].buf;
      struct json_temp_value *jt_value= ((struct json_temp_value *) values_arr->buffer) + i;

      my_free(key);
      json_temp_free(jt_value);
    }
    delete_dynamic(keys_arr);
    delete_dynamic(values_arr);
    break;
  }
  case JSON_VALUE_STRING:
  {
    my_free(v->value.string.buf);
    break;
  }
  case JSON_VALUE_NULL:
  case JSON_VALUE_TRUE:
  case JSON_VALUE_FALSE:
  {
    break;
  }
  default:
    DBUG_ASSERT(0);
  }
}


static char *
json_temp_to_string(char *buf, size_t size, struct json_temp_value *v)
{
  size_t i, used_buf_len;
  struct json_temp_object *obj;
  DBUG_ASSERT(buf);
  DBUG_ASSERT(size);
  memset(buf, 0x00, size);

  switch (v->type)
  {
  case JSON_VALUE_OBJECT:
  {
    strcat(buf, "{");
    /* TODO: for now ASSUME v is of type object. */
    obj= &v->value.object;

    for (i= 0; i < obj->keys.elements; ++i)
    {
      DYNAMIC_ARRAY *keys_arr= &obj->keys;
      DYNAMIC_ARRAY *values_arr= &obj->values;
      struct json_temp_value *jt_value= ((struct json_temp_value *) values_arr->buffer) + i;

      /* TODO: replace with a get_dynamic_ref when it exists */
      strcat(buf, "\"");
      strcat(buf, (char *)((struct json_temp_string *) keys_arr->buffer)[i].buf);
      strcat(buf, "\":");
      used_buf_len= strlen(buf);
      /* TODO: watch out for buffer overflow. */
      json_temp_to_string(buf + used_buf_len, size - used_buf_len, jt_value);
    }
    strcat(buf, "}");
    break;
  }
  case JSON_VALUE_STRING:
  {
    /*TODO string escaping ? */
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

  default:
    DBUG_ASSERT(0);
  }
  return buf;
}


int json_normalize(char *buf, size_t buf_size, const uchar *s, size_t size,
                   CHARSET_INFO *cs)
{
  json_engine_t je;
  int err= 0;
  const size_t key_buf_size= 100;
  char key_buf[100]; /* TODO */
  size_t key_len= 0;
  struct json_temp_value root;

  DBUG_ASSERT(buf);
  DBUG_ASSERT(buf_size);
  DBUG_ASSERT(s);

  buf[0]= '\0';
  memset(key_buf, 0x00, key_buf_size);
  memset(&je, 0x00, sizeof(je));
  memset(&root, 0x00, sizeof(root));

  err= json_scan_start(&je, cs, s, s + size);

  /* json_temp_malloc(DEFAULT_NUM_KEYS * sizeof(struct json_temp_string)); */

  /* first figure out the root */

  do {
    switch (je.state)
    {
    case JST_KEY:
      /* we have the key name */
      /* json_read_keyname_chr() */
      while (json_read_keyname_chr(&je) == 0)
      {
        key_buf[key_len++]= je.s.c_next;
      }

      /* After reading the key, we have a follow-up value. */
      if (json_read_value(&je))
        goto json_normalize_error;
      if (json_value_scalar(&je))
      {
        size_t je_value_len= (je.value_end - je.value_begin);
        struct json_temp_value jt_value;

        json_temp_value_type_string_init(&jt_value, (const char *)je.value_begin,
                                         je_value_len);
        /* TODO: differences between true/false/string. */
        json_temp_object_append_key_value(&root.value.object /* todo should be current, not only root. */,
                                          key_buf, key_len, &jt_value);
      }
      else
      {
        DBUG_ASSERT(0);
        /* Need to handle arrays / objects recursively? */
      }


      break;
    case JST_VALUE:
      if (json_read_value(&je))
        goto json_normalize_error;
      if (root.type == JSON_VALUE_UNINITIALIZED) {
        if (json_value_scalar(&je))
        {
          /* TODO fix in tests. */
          root.type= je.value_type;
          if (root.type == JSON_VALUE_STRING)
          {
            size_t je_value_len= (je.value_end - je.value_begin);
            json_temp_value_type_string_init(&root,
                                             (const char *)je.value_begin,
                                             je_value_len);
          }
          if (root.type == JSON_VALUE_NUMBER)
          {
            DBUG_ASSERT(0);
          }
          break;
        }

        if (je.value_type == JSON_VALUE_OBJECT)
        {
          root.type= JSON_VALUE_OBJECT;
          json_temp_object_init(&root.value.object);
        }
        else
        {
          DBUG_ASSERT(0);
          /*
          root.type= JSON_VALUE_ARRAY;
          json_temp_array_init(&root.value.array);
          */
        }
        break;
      }
      if (json_value_scalar(&je))
      {
        /* TODO fix in tests. */
        DBUG_ASSERT(0);
        break;
      }

      if (je.value_type == JSON_VALUE_OBJECT)
      {
        root.type= JSON_VALUE_OBJECT;
        json_temp_object_init(&root.value.object);
      }
      else
      {
        DBUG_ASSERT(0);
        /*
           root.type= JSON_VALUE_ARRAY;
           json_temp_array_init(&root.value.array);
         */
      }


      /* see the json_read_value() */
      break;
    case JST_OBJ_START:
       /* parser found an object (the '{' in JSON) */
      /* time to recurse! */
      break;
    case JST_OBJ_END:
      /* parser found the end of the object (the '}' in JSON) */
      /* pop recursion */
      break;
    case JST_ARRAY_START:
      /* parser found an array (the '[' in JSON) */
      break;
    case JST_ARRAY_END:
      /* parser found the end of the array (the ']' in JSON) */
      break;
    };
  } while (json_scan_next(&je) == 0);

  /* sort keys[], vals[] */
  /* for each val in vals[] */

  /* strcpy(buf, key_buf); */
  json_temp_to_string(buf, buf_size, &root);

  json_temp_free(&root);

  return err;

json_normalize_error:
  return 1; /* TODO don't leak. */
}

static void
check_json_normalize(const char *in, const char *expected)
{
  const size_t actual_size= 40;
  char actual[40]; /* C89 */

  const size_t msg_size= 100;
  char msg[100]; /* C89 */

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

static void test_json_normalize_values(void)
{
  check_json_normalize("\"foo\"", "\"foo\"");
  check_json_normalize("true", "true");
  check_json_normalize("false", "false");
  check_json_normalize("null", "null");
}


int main(void)
{

  plan(10);
  diag("Testing json_normalization.");

  test_json_normalize_values();
  test_json_normalize_single_kv();

  return exit_status();
}
