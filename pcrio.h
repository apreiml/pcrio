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

// typedef struct pcr_file PCR_FILE;

/**
 * Get a string describing the error. TODO
 */
extern const char* pcr_error_message(pcr_error_code err);

extern struct pcr_file *pcr_read_file(const char *filename, pcr_error_code *err);
extern void pcr_write_file(const char *filename, struct pcr_file *pfile, pcr_error_code *err);

extern void pcr_free(struct pcr_file *pfile);

/**
 * Iterates through the string nodes to get the most common culture id.
 * 
 * @return -1 on error or if no data is present. //TODO or 0??
 */
extern int32_t pcr_get_default_culture_id(struct pcr_file *pfile);

/**
 * Looks up the codepage of given culture in the version info.
 */
extern uint32_t pcr_get_default_codepage(struct pcr_file *pfile, uint32_t culture_id);

/**
 * 
 * @param culture_id if -1 take the culture with lowest id //TODO is this necessary?
 * 
 * @return pcr_string with value = NULL
 */
extern pcr_string pcr_get_string(const struct pcr_file *pfile, uint32_t id, int32_t culture_id);

/**
 * The string needs to be encoded. Creates a new name and/or language node if
 * one/both of them is/are missing.
 */
extern pcr_error_code pcr_set_string(struct pcr_file *pfile, uint32_t id, uint32_t culture_id, const pcr_string str);

extern void pcr_debug_info(struct pcr_file *pfile);

#endif // PCRIO_H
