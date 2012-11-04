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

typedef struct pcr_string {
  
  char *value;
  uint32_t size;
  uint32_t codepage;  
  
} Pcr_string;

#define PCR_SUCCESS(x) (x == PCR_ERROR_NONE)
#define PCR_FAILURE(x) (x != PCR_ERROR_NONE)

// typedef Pcr_file PCR_FILE;

/**
 * Get a string describing the error. 
 */
extern const char* pcr_error_message(pcr_error_code err);

extern Pcr_file *pcr_read_file(const char *filename, pcr_error_code *err);
extern void pcr_write_file(const char *filename, Pcr_file *pfile, pcr_error_code *err);

extern void pcr_free(Pcr_file *pfile);
extern void pcr_free_string_value(Pcr_string string); 

/**
 * 
 */
extern const Culture_info_array* pcr_get_culture_info(Pcr_file *pfile);

/**
 * 
 * @param culture_id if -1 take the culture with lowest id //TODO is this necessary?
 * 
 * @return copy of string or if not found: Pcr_string with value = NULL
 */
extern Pcr_string pcr_get_string(const Pcr_file *pfile, uint32_t id, int32_t culture_id);

/**
 * The string needs to be encoded. Creates a new name and/or language node if
 * one/both of them is/are missing.
 */
extern pcr_error_code pcr_set_string(Pcr_file *pfile, uint32_t id, uint32_t culture_id, const Pcr_string str);

// TODO new string api

extern const Culture_info * pcr_get_default_culture(const Pcr_file *pfile);
extern void pcr_set_default_culture(Pcr_file *pf, Culture_info cult_inf);
  
extern uint32_t pcr_get_string_size (Pcr_file *pf, uint32_t id);
extern uint32_t pcr_get_string_sizeC (Pcr_file *pf, uint32_t id, uint32_t culture_id);
    
/// return number of characters read
// extern uint32_t pcr_get_string (const Pcr_file *pf, uint32_t id, char *buff, uint32_t buff_size);  // set default culture
extern uint32_t pcr_get_stringC (const Pcr_file *pf, uint32_t id, uint32_t culture_id, char *buff, uint32_t buff_size);


#endif // PCRIO_H
