
#include <check.h>
#include <string.h>
#include "../pcrio.h"

#define LANG_EN 1033

#define L_AOE "lang/aoe/language.dll"

struct pcr_file * test_read_file(const char *filename, pcr_error_code *err)
{
  struct pcr_file *pcr_file = NULL;

  pcr_file = pcr_read_file(filename, err);

  fail_unless (PCR_SUCCESS(*err), "failed to read %s", filename);

  return pcr_file;
}

void test_check_string(struct pcr_file *pf, uint32_t id, int32_t lang, const char *str)
{
  pcr_string read_str;
  
  read_str = pcr_get_string(pf, id, lang);
  
  fail_if(read_str.value == NULL);
  
  fail_unless(strcmp(read_str.value, str) == 0, 
              "Read string: \"%s\" differs from: \"%s\".", read_str.value, str);
  
  pcr_free_string_value(read_str);
}

void test_read_only(const char *filename)
{
  pcr_error_code err = PCR_ERROR_NONE;
  pcr_free(test_read_file(filename, &err));
}


START_TEST (test_pcrio_read)
{
  test_read_only(L_AOE);
  test_read_only("lang/aok/language.dll");
  test_read_only("lang/aok/language_x1.dll");
  test_read_only("lang/aok/language_x1_p1.dll");
  test_read_only("lang/sw/language.dll");
  test_read_only("lang/sw/language_x1.dll");
}
END_TEST

START_TEST (test_pcrio_rw_strings)
{
  pcr_error_code err = PCR_ERROR_NONE;
  struct pcr_file *pf = NULL;
  
  pf = test_read_file(L_AOE, &err);
  
  pcr_string str;
  str.codepage = 0;
  str.value = "test";
  str.size = strlen(str.value);
  
  pcr_set_string(pf, 9999, LANG_EN, str);
  
  pcr_write_file("out.dll", pf, &err);
  
  fail_unless(PCR_SUCCESS(err), NULL);
  
  pcr_free(pf);
  
  pf = test_read_file("out.dll", &err);
  
  test_check_string(pf, 101, LANG_EN, "1");
  test_check_string(pf, 54518, LANG_EN, "Click to order units to repair a building or boat.");
  test_check_string(pf, 9999, LANG_EN, "test");
  
}
END_TEST

Suite * pcrio_suite (void)
{
  Suite *s = suite_create ("pcrio");

  TCase *tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_pcrio_read);
  tcase_add_test(tc_core, test_pcrio_rw_strings);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;

  Suite *s = pcrio_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? 0 : -1;
}

