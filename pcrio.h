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
  PCR_ERROR_BAD_ALLOC,
  PCR_ERROR_READ,
  PCR_ERROR_WRITE,
  PCR_ERROR_CORRUPT_FILE,
  PCR_ERROR_INVALID_SIGNATURE,
  PCR_ERROR_UNSUPPORTED
};

typedef enum pcr_error pcr_error_code;

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
 * Not fully functional! Language parmaeter will be ignored, the first language entry will be 
 * taken instead.
 */
extern struct enc_string pcr_get_string(const struct pcr_file *pfile, uint32_t id, uint32_t language);

//TODO language api
/**
 * The string needs to be encoded. The codepage can be found in the enc_string struct 
 * given by pcr_get_string.
 * 
 * TODO: language will be ignored for now. First language entry will be taken.
 */
extern void pcr_set_string(struct pcr_file *pfile, uint32_t id, uint32_t language, const char *str);

extern void pcr_debug_info(struct pcr_file *pfile);

#endif // PCRIO_H
