/*
    Copyright (c) 2012, Armin Preiml
    
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted (subject to the limitations in the
    disclaimer below) provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the
      distribution.

    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

    NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
    GRANTED BY THIS LICENSE.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
    HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
    WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
    OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
    IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PCRIO_H
#define PCRIO_H

#include <stdint.h>

#include "pcrdef.h"

enum pcr_error {
  PCR_ERROR_NONE = 0,
  PCR_ERROR_BAD_ALLOC = 1,
  PCR_ERROR_READ = 2,
  PCR_ERROR_WRITE = 3,
  PCR_ERROR_CORRUPT_FILE = 4,
  PCR_ERROR_INVALID_SIGNATURE = 5,
  PCR_ERROR_UNSUPPORTED = 6
};

typedef enum pcr_error pcr_error_code;

typedef struct pcr_string_ {
  
  char *value;
  uint32_t size;
  uint32_t codepage;  
  
} pcr_string;

#define PCR_SUCCESS(x) (x == PCR_ERROR_NONE)
#define PCR_FAILURE(x) (x != PCR_ERROR_NONE)

/**
 * Get a string describing the error. 
 */
extern const char* pcr_error_message(pcr_error_code err);

extern struct pcr_file *pcr_read_file(const char *filename, pcr_error_code *err);
extern void pcr_write_file(const char *filename, struct pcr_file *pfile, pcr_error_code *err);

extern void pcr_free(struct pcr_file *pfile);
extern void pcr_free_string_value(pcr_string string); 

/**
 * TODO better name 
 */
extern const struct language_info_array* pcr_get_language_info(const struct pcr_file *pfile);

/**
 * The string needs to be encoded. Creates a new name and/or language node if
 * one/both of them is/are missing.
 */
extern pcr_error_code pcr_set_string(struct pcr_file *pfile, uint32_t id, uint32_t language_id, const pcr_string str);

/**
 * Get the default language. If there is only one language available on read, it will
 * be set as default. If not the language needs to be set using pcr_set_default_language.
 * 
 * @param pfile 
 * @return ptr to language struct or NULL if none is set
 */
extern const struct pcr_language * pcr_get_default_language(const struct pcr_file *pfile);

//TODO (if id is not unique use languageL
extern void pcr_set_default_language(struct pcr_file* pf, uint32_t language_id);
extern void pcr_set_default_languageL(struct pcr_file *pf, struct pcr_language lang);

//TODO
extern uint32_t pcr_get_str_codepage(const struct pcr_file *pf, uint32_t id);
extern uint32_t pcr_get_str_codepageL(const struct pcr_file *pf, uint32_t id, uint32_t language_id);
  
/**
 * Returns the string length. 
 * 
 * @return Number of characters (without ending \0) or 0 if not found. Or -1 if language id not set.
 */
extern int32_t pcr_get_strlen(const struct pcr_file *pf, uint32_t id);

/**
 * Method for getting the length of a string with language id as additional parameter.
 * 
 * @return Length of string (without ending \0) or 0 if not found.
 */
extern uint16_t pcr_get_strlenL(const struct pcr_file *pf, uint32_t id, uint32_t language_id);
    
/**
 * If the buffer is > strlen, then then the \0 will be copied too.
 * 
 * @return number of bytes successfully read. 
 * @return -1 if codepage differs from default language.
 * @return -2 if default language is not set
 */
extern int32_t pcr_get_string(const struct pcr_file *pf, uint32_t id, char *buff, uint32_t buff_size); 

/** 
 * See pcr_get_string. This function has the language_id as additional parameter.
 * 
 * @return number of bytes successfully read or -1 if codepage is not unique for given language
 */
extern int32_t pcr_get_stringL(const struct pcr_file *pf, uint32_t id, uint32_t language_id, char *buff, uint32_t buff_size);

/**
 * If pcr_get_string or pcr_get_stringL fail because of the codepage issue. You
 * can cleary specify the language with codepage using the pcr_language struct.
 * It may only be necessary to use this function if there are strings having
 * different codepages, but exactly the same language.
 * 
 * @return number of bytes successfully read or -1 if codepage differs
 */
extern int32_t pcr_get_stringS(const struct pcr_file *pf, uint32_t id, struct pcr_language lang, char *buff, uint32_t buff_size);


#endif // PCRIO_H
