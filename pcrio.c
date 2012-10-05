/*
    Copyright (c) 2012, Armin Preiml
    
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted (subject to the limitations in the
    disclaimer below) provided that the following conditions are met:

    * Redistributions of source err must retain the above copyright
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcrio.h"

#define INT32_HIGH_BYTE 2147483648u

// TODO: is 16 const?
#define MAX_STRINGS_PER_LEAF 16

#define UNKNOWN_HEADER_SIZE 0x98
#define SUPPORTED_OPTIONAL_HEADER_SIZE 224

#define SECTION_NAME_RESOURCE ".rsrc"

enum rsrc_node_identifier {
  TREE_NODE_IDENTIFIER_ID = 0,
  TREE_NODE_IDENTIFIER_NAME = 1

};

struct rsrc_section_size { 
  uint32_t s_tree;
  uint32_t s_data_description;
  uint32_t s_directory_strings;
  uint32_t s_data;
  
  uint32_t section_start_pos;
};

//TODO: iterator?
//TODO: IMAGE_SECTION_HEADER.name needs special treatment!

//TODO: documentation
//TODO: cleanup source err (variable name, coding style)


/* 
 * misc utils
 */

void * pcr_malloc(size_t size, enum pcr_error *err);
void * pcr_realloc(void *ptr, size_t size, enum pcr_error *err);

void pcr_fread(void *ptr, size_t size, size_t nmemb, FILE *stream, enum pcr_error *err);
void pcr_fwrite(const void*ptr, size_t size, size_t nmemb, FILE *stream, enum pcr_error *err);

void pcr_zero_pad(FILE *stream, uint32_t pos, enum pcr_error *err);

/*
 * compare functions
 */

int pcr_comp_image_secion_headers (const void *a, const void *b);
int pcr_comp_id_tree_nodes (const void *a, const void *b);

/*
 * read functions
 */

void pcr_read_optional_header(struct pcr_file *pfile, FILE *file, pcr_error_code *err);
void pcr_read_section_table(struct pcr_file *pfile, FILE *file, pcr_error_code *err);
void pcr_read_section_data(struct pcr_file *pfile, FILE *file, pcr_error_code *err);
void pcr_read_rsrc_section(struct pcr_file *pcr_file, FILE *file, pcr_error_code *err);
 
struct resource_tree_node *pcr_read_rsrc_tree(FILE *file, enum pcr_error *err, 
      long section_offset, int level, enum resource_type type);

struct resource_tree_node * pcr_read_sub_tree(FILE *file, enum pcr_error *err, long section_offset,
                  struct resource_directory_entry *directory_entry, 
                  enum rsrc_node_identifier identified_by, int level, enum resource_type type);              

struct resource_directory_entry * pcr_read_rsrc_directory_entries(FILE *file, int count, 
                                    enum pcr_error *err);

struct resource_data* pcr_read_rsrc_data(FILE *file, enum pcr_error *err, uint32_t size, 
                                         enum resource_type type);

struct rsrc_string *pcr_read_string(FILE *file, enum pcr_error *err);

/*
 * pre write functions
 */

struct rsrc_section_size pcr_prepare_rsrc_data(struct pcr_file *pcr_file, enum pcr_error *err_code);
void pcr_prepare_rsrc_node(struct resource_tree_node *node, 
                               enum pcr_error *err_code, struct rsrc_section_size *size);

/*
 * write functions
 */

void pcr_write_section_data(struct pcr_file *pcr_file, FILE *stream, 
                          enum pcr_error *err, struct rsrc_section_size size);

void pcr_write_rsrc_section(struct pcr_file *pcr_file, FILE *stream, 
                          enum pcr_error *err, struct rsrc_section_size size);

void pcr_write_rsrc_node(struct resource_tree_node *node, FILE *stream, 
                          enum pcr_error *err_code, struct rsrc_section_size size);

void pcr_write_data_description(struct resource_tree_node *node, FILE *stream, 
                          enum pcr_error *err_code, struct rsrc_section_size size);

void pcr_write_directory_strings(struct resource_tree_node *node, FILE *stream, 
                          enum pcr_error *err_code, struct rsrc_section_size size);

void pcr_write_rsrc_section_data(struct resource_tree_node *node, FILE *stream, 
                          enum pcr_error *err_code, struct rsrc_section_size size);


void pcr_write_string(struct rsrc_string *str, FILE *stream, enum pcr_error *err_code);
void pcr_write_rsrc_data(struct resource_data *str, FILE *stream, enum pcr_error *err_code);

/*
 * initialization functions
 */

void pcr_init_directory_table(struct resource_directory_table *table_ptr);

/*
 * free
 */

void pcr_free_resource_tree_node(struct resource_tree_node *node);
void pcr_free_resource_data(struct resource_data *resource_data);
void pcr_free_resource_string(struct rsrc_string *str);

/*
 * access functions
 */

struct image_section_header * pcr_get_section_header(struct pcr_file *pfile, const char *name);
struct resource_tree_node* pcr_get_sub_id_node(const struct resource_tree_node *node, uint32_t id);

/*
 * misc utils
 */

/**
 */
const char* pcr_error_message(pcr_error_code err)
{
  switch(err)
  {
    case PCR_ERROR_NONE: return "Success"; break;
    case PCR_ERROR_BAD_ALLOC: return "Bad alloc!"; break;
    case PCR_ERROR_READ: return "Unable to read file"; break;
    case PCR_ERROR_WRITE: return "Unable to write file"; break;
    case PCR_ERROR_CORRUPT_FILE: return "Corrupt file"; break;
    case PCR_ERROR_INVALID_SIGNATURE: 
      return "Invalid signature (corrupt file?)"; break;
    case PCR_ERROR_UNSUPPORTED: 
      return "Unsupported file (missing functionality)"; break;
    default:
      return "No error message. Did you initialize the error?"; break;
  }
}

/**
 * "safe" malloc with error handling. Allocation will be skipped if 
 *  error err != NONE
 */
void * pcr_malloc(size_t size, enum pcr_error *err)
{
  void *alloc_var = NULL;
  
  if (*err == PCR_ERROR_NONE && size > 0)
  {
    alloc_var = malloc(size);
    
    if (alloc_var == NULL)
      *err = PCR_ERROR_BAD_ALLOC;
  }
  
  return alloc_var;
}

/**
 * "safe" realloc with error handling. *ptr will not be freed on error!
 */
void * pcr_realloc(void *ptr, size_t size, enum pcr_error *err)
{
  void *new_alloc = NULL;

  if (*err == PCR_ERROR_NONE)
  {
    new_alloc = realloc(ptr, size);

    if (new_alloc == NULL)
      *err = PCR_ERROR_BAD_ALLOC;
  }

  return new_alloc;
}
  
/**
 * fread with enum pcr_error checking
 */
void pcr_fread(void *ptr, size_t size, size_t nmemb, FILE *stream, 
               enum pcr_error *err)
{
  if (*err == PCR_ERROR_NONE)
  {
    if (fread(ptr, size, nmemb, stream) < nmemb)
      *err = PCR_ERROR_READ;
  }
}

/**
 * fwrite with enum pcr_error checking
 */
void pcr_fwrite(const void*ptr, size_t size, size_t nmemb, FILE *stream,
                enum pcr_error *err)
{
  if (*err == PCR_ERROR_NONE)
  {
    if (fwrite(ptr, size, nmemb, stream) < nmemb)
      *err = PCR_ERROR_WRITE;
  }
}

/**
 * Fills 0 until pos.
 */
void pcr_zero_pad(FILE *stream, uint32_t pos, enum pcr_error *err)
{
  char empty = 0;
  long lpos = pos;
  
  while (ftell(stream) >= 0 && ftell(stream) < lpos)
     pcr_fwrite(&empty, 1, 1, stream, err);
  
  if (ftell(stream) == -1)
    *err = PCR_ERROR_WRITE;
}

/*
 * compare functions
 */

/**
 * Compare function to sort section headers ascending by pointer_to_raw_data.
 */
int pcr_comp_image_secion_headers (const void *a, const void *b)
{
  return ((struct image_section_header *)a)->pointer_to_raw_data -
         ((struct image_section_header *)b)->pointer_to_raw_data; 
}

/**
 * Compare function that compares the id of Tree nodes
 */
int pcr_comp_id_tree_nodes (const void *a, const void *b)
{
  return (*(struct resource_tree_node **)a)->id - 
         (*(struct resource_tree_node **)b)->id;
}

int pcr_comp_name_tree_nodes (const void *a, const void *b)
{
  return strcmp((*(struct resource_tree_node **)a)->name->str, 
                (*(struct resource_tree_node **)b)->name->str); 
}

/**
 * 
 */
void pcr_debug_info(struct pcr_file *pfile)
{
        
    printf("\nSection table: \n");
    
    int i;
    for (i=0; i<pfile->image_file_header.number_of_sections; i++)
    {
      printf("* Name: %s\n", pfile->section_table[i].name);
      printf("  Virtual address:  0x%x\n", pfile->section_table[i].virtual_adress);
      printf("  Virtual size:     0x%x\n", pfile->section_table[i].virtual_size);
      printf("  Ptr to raw data:  0x%x\n", pfile->section_table[i].pointer_to_raw_data);
      printf("  Size of raw data: 0x%x\n", pfile->section_table[i].size_of_raw_data);
    }
    
    printf("\n");
}

/*
 * read functions
 */

/**
 * 
 */
struct pcr_file *pcr_read_file(const char *filename, pcr_error_code *err)
{
  FILE *file = NULL;
  struct pcr_file *pfile = NULL;
  
  if (PCR_FAILURE(*err))
    return NULL;
  
  pfile = (struct pcr_file *) pcr_malloc(sizeof(struct pcr_file), err);
  
  pfile->rm_stub = NULL;
  pfile->image_optional_header32 = NULL;
  pfile->section_table = NULL;
  pfile->rsrc_section_data = NULL;
  pfile->section_data = NULL;
  
  file = fopen(filename, "rb");
  
  if (file == NULL)
    *err= PCR_ERROR_READ;
  else
  {
    pcr_fread(&pfile->dos_header, sizeof(struct image_dos_header), 1, file, err);
    
    unsigned int rm_stub_size = pfile->dos_header.e_lfanew - sizeof(struct image_dos_header);
    pfile->rm_stub = (char *)pcr_malloc(rm_stub_size, err);
    
    pcr_fread(pfile->rm_stub, rm_stub_size, 1, file, err);    
    pcr_fread(pfile->signature, sizeof(char), 4, file, err);
    pcr_fread(&pfile->image_file_header, sizeof(struct image_file_header), 1, file, err);
    
    pcr_read_optional_header(pfile, file, err);
    pcr_read_section_table(pfile, file, err);
    pcr_read_section_data(pfile, file, err);
    
    fclose(file);
  }
  
  return pfile;
}


/**
 * Allocate and read optional header if available
 */
void pcr_read_optional_header(struct pcr_file *pfile, FILE *file, pcr_error_code *err)
{ 
  uint16_t magic = 0;
  
  if (*err== PCR_ERROR_NONE && pfile->image_file_header.size_of_optional_header > 0)
  {
    if (pfile->image_file_header.size_of_optional_header !=  SUPPORTED_OPTIONAL_HEADER_SIZE)
    {
      *err= PCR_ERROR_UNSUPPORTED;
      return;
    }
    
    pcr_fread(&magic, sizeof(uint16_t), 1, file, err);
    
    if (magic != IMAGE_OPTIONAL_HDR32_MAGIC)
      *err= PCR_ERROR_UNSUPPORTED;
    else
    {
      pfile->image_optional_header32 = (struct image_optional_header32 *)
          pcr_malloc(sizeof(struct image_optional_header32), err);
        
      if (*err== PCR_ERROR_NONE)
      {
        struct image_optional_header32 *opt_header = pfile->image_optional_header32;
        
        opt_header->magic = magic;
        
        // skipping magic on read
        pcr_fread(&opt_header->major_linker_version, 
                  sizeof(struct image_optional_header32) - sizeof(magic), 1, file, err);
      }
            
    }
  }
}

/**
 * Read and sort section table
 */
void pcr_read_section_table(struct pcr_file *pfile, FILE *file, pcr_error_code *err)
{
  if (PCR_FAILURE(*err))
    return;
  
  uint16_t num_sec = pfile->image_file_header.number_of_sections;
        
  pfile->section_table = (struct image_section_header *)pcr_malloc(sizeof(struct image_section_header) * num_sec, err);
  pcr_fread(pfile->section_table, sizeof(struct image_section_header), num_sec, file, err);
  
  qsort(pfile->section_table, num_sec, sizeof(struct image_section_header),  
        pcr_comp_image_secion_headers);
}

/**
 * 
 */
void pcr_read_section_data(struct pcr_file *pfile, FILE *stream, pcr_error_code *err)
{
  if (PCR_FAILURE(*err))
    return;
  
  int num_sec, i; 
  
  num_sec = pfile->image_file_header.number_of_sections;
  
  pfile->section_data = (char **)pcr_malloc(sizeof(char *) * num_sec, err);
  
  for (i=0; i<num_sec; i++)
  {
    struct image_section_header *sec = &pfile->section_table[i];
    
    fseek(stream, sec->pointer_to_raw_data, SEEK_SET);
    
    if (strcmp(SECTION_NAME_RESOURCE, sec->name) == 0)
    {
      pfile->section_data[i] = NULL;
      
      pcr_read_rsrc_section(pfile, stream, err);
    }
    else
    { 
      pfile->section_data[i] = (char *)pcr_malloc(sec->virtual_size, err);
        
      pcr_fread(pfile->section_data[i], sec->virtual_size, 1, stream, err);
    }
  }
}

/**
 * 
 */
void pcr_read_rsrc_section(struct pcr_file *pfile, FILE *file, pcr_error_code *err)
{
  pfile->rsrc_section_data = NULL;
 
  if (PCR_FAILURE(*err))
    return;

  struct image_section_header *rsrc_header;
  
  rsrc_header = pcr_get_section_header(pfile, SECTION_NAME_RESOURCE);
    
  if (rsrc_header != NULL)
  {
    pfile->rsrc_section_data = (struct resource_section_data *)pcr_malloc(sizeof(struct resource_section_data), err);
  
    pfile->rsrc_section_data->root_node = 
      pcr_read_rsrc_tree(file, err, ftell(file), 0, RESOURCE_TYPE_UNKNOWN);
  }
}

/**
 * reas a directory table and recoursivly reads its children
 */
struct resource_tree_node * pcr_read_rsrc_tree(FILE *file, pcr_error_code *err_code, 
                       long section_offset, int level, enum resource_type type)
{
  if (*err_code != PCR_ERROR_NONE)
    return NULL;
  
  struct resource_tree_node *node = NULL;  

  node = (struct resource_tree_node *)pcr_malloc(sizeof(struct resource_tree_node), err_code);
 
  if (node != NULL)
  {
    uint16_t num_id_entries, num_name_entries;
    struct resource_directory_entry *name_entries, *id_entries;
    
    node->name = NULL;
    node->id_entries = NULL;
    node->name_entries = NULL;
    node->resource_data = NULL;
  
    pcr_fread(&node->directory_table, sizeof(struct resource_directory_table), 1, file, err_code);

    num_id_entries = node->directory_table.number_of_id_entries;
    num_name_entries = node->directory_table.number_of_name_entries;
  
    name_entries = pcr_read_rsrc_directory_entries(file, num_name_entries, err_code);
    id_entries = pcr_read_rsrc_directory_entries(file, num_id_entries, err_code);
  
    node->name_entries = (struct resource_tree_node **)pcr_malloc(sizeof(struct resource_tree_node *) * num_name_entries, err_code);
    node->id_entries = (struct resource_tree_node **)pcr_malloc(sizeof(struct resource_tree_node *) * num_id_entries, err_code);
    
    if (*err_code != PCR_ERROR_NONE)
    {
      free(node->name_entries);
      free(node->id_entries);
      free(name_entries);
      free(id_entries);
      free(node);
      return NULL;
    }
    
    int i;
    for (i=0; i < num_name_entries; i++)
      node->name_entries[i] = pcr_read_sub_tree(file, err_code, section_offset, &name_entries[i], 
                                                TREE_NODE_IDENTIFIER_NAME, level, type);
  
    for (i=0; i < num_id_entries; i++)
      node->id_entries[i] = pcr_read_sub_tree(file, err_code, section_offset, &id_entries[i], 
                                              TREE_NODE_IDENTIFIER_ID, level, type);
  
    free(name_entries);
    free(id_entries);
  }
  
  return node;
}


/**
 * Reads a node using data from givne directory_entry and recursivly loads 
 * subdirectories or leaf data.
 */
struct resource_tree_node * 
pcr_read_sub_tree(FILE *file, enum pcr_error *err_code, long section_offset,
                  struct resource_directory_entry *directory_entry, 
                  enum rsrc_node_identifier identified_by, int level, enum resource_type type)
{
  if (*err_code != PCR_ERROR_NONE)
    return NULL;
  
  struct resource_tree_node *subtree = NULL;
  uint32_t rva_child;
  
  level ++;
  
  if (level == 1 && directory_entry->id == RESOURCE_TYPE_STRINGS)
    type = RESOURCE_TYPE_STRINGS;
  
  rva_child = directory_entry->rva;
    
  if (rva_child & INT32_HIGH_BYTE)    // node is a subdirectory
  {
    rva_child = rva_child - INT32_HIGH_BYTE;
    
    fseek(file, section_offset + rva_child, SEEK_SET);
    
    subtree = pcr_read_rsrc_tree(file, err_code, section_offset, level, type);
    
  }
  else // node contains data (leaf)
  {
    struct resource_data_entry data_entry;
    struct resource_data* data = NULL;
    
    fseek(file, section_offset + rva_child, SEEK_SET);
    
    pcr_fread(&data_entry, sizeof(struct resource_data_entry), 1, file, err_code);
    
    fseek(file, data_entry.data_rva, SEEK_SET);
    
    data = pcr_read_rsrc_data(file, err_code, data_entry.size, type);
    
    if (data != NULL)
      data->data_entry = data_entry;
    
    subtree = (struct resource_tree_node *)pcr_malloc(sizeof(struct resource_tree_node), err_code);
    
    if (subtree != NULL)
    {    
      pcr_init_directory_table(&subtree->directory_table);
      
      subtree->id_entries = NULL;
      subtree->name_entries = NULL;
      subtree->name = NULL;
    
      subtree->resource_data = data;
    }
  }
    
  // node identification:
  
  if (subtree != NULL)
  {
    if (identified_by == TREE_NODE_IDENTIFIER_NAME)
    {
      long name_rva = directory_entry->id - INT32_HIGH_BYTE;
      name_rva += section_offset;
      
      fseek(file, name_rva, SEEK_SET);
      
      subtree->name = pcr_read_string(file, err_code);
    }
    else if (identified_by == TREE_NODE_IDENTIFIER_ID) 
    {
      subtree->id = directory_entry->id;
    }
    
    subtree->directory_entry = *directory_entry;
  }
  
  return subtree;
}

/**
 * Reads an array of directory entries.
 */
struct resource_directory_entry * pcr_read_rsrc_directory_entries(FILE *file, int count, 
                                    enum pcr_error *err_code)
{
  if (*err_code != PCR_ERROR_NONE || count <= 0)
    return NULL;
  
  struct resource_directory_entry *entries = NULL;
  
  entries = (struct resource_directory_entry *)
      pcr_malloc(sizeof(struct resource_directory_entry) * count, err_code);
  pcr_fread(entries, sizeof(struct resource_directory_entry), count, file, err_code);
  
  return entries;
}

/**
 * read either a string or raw data from file
 */
struct resource_data *pcr_read_rsrc_data(FILE *file, enum pcr_error *err_code, 
                                   uint32_t size, enum resource_type type)
{
  struct resource_data *data = NULL;
    
  if (size > 0 && *err_code == PCR_ERROR_NONE)
  {
    char *raw_data = NULL;
    struct rsrc_string **strings = NULL;
    uint16_t string_count = 0; 
    int i;
    
    if (type == RESOURCE_TYPE_STRINGS)
    {
      // placeholder for realloc error handling
      struct rsrc_string **re_strings = NULL; 
      
      uint32_t area_start_pos = ftell(file);
      
      while (ftell(file) < (area_start_pos + size))
      {
        re_strings = (struct rsrc_string **)pcr_realloc(strings, 
                      sizeof(struct rsrc_string *) * (string_count+1), err_code); 
          
        if (*err_code != PCR_ERROR_NONE)
          break;

        strings = re_strings;
          
        strings[string_count] = pcr_read_string(file, err_code);
        
        string_count++;
      }
      
      if (*err_code != PCR_ERROR_NONE)
      {
        for (i=0; i<string_count; i++)
          pcr_free_resource_string(strings[i]);
          
        free(strings);
      }
    }
    else // other types
    {
      raw_data = (char*)pcr_malloc(size, err_code);
      pcr_fread(raw_data, size, 1, file, err_code);
    }
    
    data = (struct resource_data *)pcr_malloc(sizeof(struct resource_data), err_code);
   
    if (data != NULL)
    {
      data->strings = strings;
      data->number_of_strings = string_count;
      data->raw_data = raw_data;
      data->type = type;
    }
  }
  
  return data;
}

/**
 * Reads a single string from stream. Strings are stored word aligned. 
 * Read strings are finished with \0.
 */
struct rsrc_string *pcr_read_string(FILE *file, enum pcr_error *err_code)
{
  struct rsrc_string *string = (struct rsrc_string *)
      pcr_malloc(sizeof(struct rsrc_string), err_code);
  
  pcr_fread(&string->size, sizeof(uint16_t), 1, file, err_code);
  string->str = (char *)pcr_malloc(sizeof(char) * (string->size+1), err_code);
      
  if (*err_code == PCR_ERROR_NONE)
  {
    int i;
    
    for (i=0; i<string->size; i++)
    {
      pcr_fread(&string->str[i], sizeof(char), 1, file, err_code);
      
      // skip 1 byte because strings are stored word aligned
      fseek(file, 1, SEEK_CUR);
    }
        
    string->str[string->size] = '\0';
  }
  
  return string;
}

/*
 * pre write functions
 */

/**
 * Calculates sizes and updates rvas. Data and name rvas will be relative.
 * They have to be updated on write.
 */
struct rsrc_section_size pcr_prepare_rsrc_data(struct pcr_file *pcr_file, enum pcr_error *err_code)
{
  struct rsrc_section_size rs_size;
  struct image_section_header *rsrc_header;
  
  rs_size.s_tree = 0;
  rs_size.s_data_description = 0;
  rs_size.s_directory_strings = 0;
  rs_size.s_data = 0;
  rs_size.section_start_pos = 0;
  
  if (*err_code == PCR_ERROR_NONE)
  {
    rsrc_header = pcr_get_section_header(pcr_file, SECTION_NAME_RESOURCE);
    
    if (rsrc_header)
      rs_size.section_start_pos = rsrc_header->pointer_to_raw_data;
  
    pcr_prepare_rsrc_node(pcr_file->rsrc_section_data->root_node, err_code, &rs_size);
  }
  
  return rs_size;
}

/**
 * recursivly update rvas and sizes
 */
void pcr_prepare_rsrc_node(struct resource_tree_node *node, enum pcr_error *err_code, 
                           struct rsrc_section_size *size)
{
  int i = 0;
    
  if (node->name == NULL)
  {
    node->directory_entry.id = node->id;
  }
  else
  {
    node->directory_entry.id = size->s_directory_strings; 
    
    size->s_directory_strings += node->name->size * 2 + sizeof(uint16_t);
  }
  
  if (node->resource_data == NULL) // node
  {
    
    node->directory_entry.rva = INT32_HIGH_BYTE | size->s_tree;
    
    uint32_t rva_next_node = 0;
    rva_next_node += node->directory_table.number_of_id_entries;
    rva_next_node += node->directory_table.number_of_name_entries;
    rva_next_node *= sizeof(struct resource_directory_entry);
    rva_next_node += sizeof(struct resource_directory_table);
        
    size->s_tree += rva_next_node;
    
    for (i=0; i<node->directory_table.number_of_name_entries; i++)
      pcr_prepare_rsrc_node(node->name_entries[i], err_code, size); 
    
    for (i=0; i<node->directory_table.number_of_id_entries; i++)
      pcr_prepare_rsrc_node(node->id_entries[i], err_code, size);
  }
  else // leaf
  {
    node->directory_entry.rva = size->s_data_description;
    
    size->s_data_description += sizeof(struct resource_data_entry);
    
    if (node->resource_data->type == RESOURCE_TYPE_STRINGS)
    {
      uint32_t act_size = 0;
      for(i=0; i<node->resource_data->number_of_strings; i++)
      {
        act_size += node->resource_data->strings[i]->size *2;
        act_size += 2;
      }
        
      if (act_size != node->resource_data->data_entry.size)
      {
        printf("Warning: Wrong string size %d act %d (Word aligned?)\n", 
               node->resource_data->data_entry.size, act_size);
        
        node->resource_data->data_entry.size = act_size;
      }
    }
    
    node->resource_data->data_entry.data_rva = size->s_data;
    size->s_data += node->resource_data->data_entry.size;
  }
}

/**
 * updates section adress and sizes
 */
void pcr_update_section_table(struct pcr_file *pfile, struct rsrc_section_size rs_size)
{
  uint32_t i, virtual_rsrc_size, raw_rsrc_size, sec_algin, raw_diff;
  struct image_section_header *rsrc_sh;
  
  virtual_rsrc_size = rs_size.s_data + rs_size.s_data_description +
                      rs_size.s_directory_strings + rs_size.s_tree;
                      
  sec_algin = pfile->image_optional_header32->section_alignment;
  
  raw_rsrc_size = virtual_rsrc_size / sec_algin * sec_algin;
  
  if (virtual_rsrc_size % sec_algin > 0)
    raw_rsrc_size += sec_algin;
  
  printf("\nVirtual size: 0x%x\nRaw Size: 0x%x\n", virtual_rsrc_size, raw_rsrc_size);
  
  rsrc_sh = pcr_get_section_header(pfile, SECTION_NAME_RESOURCE);
  
  raw_diff = rsrc_sh->size_of_raw_data - raw_rsrc_size;
  
  printf("Raw diff: 0x%x\n\n", raw_diff);
  
  rsrc_sh->virtual_size = virtual_rsrc_size;

  if (raw_diff != 0)
  {
    uint16_t num_sec;
  
    rsrc_sh->size_of_raw_data = raw_rsrc_size;
    
    num_sec = pfile->image_file_header.number_of_sections;
  
    // update section table
    for (i=0; i<num_sec; i++)
    {
      struct image_section_header *sec = &pfile->section_table[i];
    
      if (strcmp(SECTION_NAME_RESOURCE, sec->name) != 0 && sec->virtual_adress > rsrc_sh->virtual_adress)
      {
        sec->virtual_adress += raw_diff;
        sec->pointer_to_raw_data += raw_diff;
      }
    }
    
    // update data directory
    pfile->image_optional_header32->data_directory[DATA_DIRECTORY_ID_RESOURCE].size = raw_rsrc_size;
    
    for (i=0; i<DATA_DIRECTORY_COUNT; i++)
    {
      struct image_data_directory *dir = &pfile->image_optional_header32->data_directory[i];
      
      if (dir->rva > pfile->image_optional_header32->data_directory[DATA_DIRECTORY_ID_RESOURCE].rva)
      {
        dir->rva += raw_diff;
      }
    }
    
    // file alignmend
    if (pfile->image_optional_header32->file_alignment != sec_algin)
      printf("TODO: File alignmend\n"); //TODO
  }
}

/*
 * Write functions
 */

/**
 * 
 */
void pcr_write_file(const char *filename, struct pcr_file *pfile, pcr_error_code *err)
{
  FILE *stream = NULL;
  
  if (pfile == NULL || PCR_FAILURE(*err))
    return;
  
  stream = fopen(filename, "wb");
  
  if (stream == NULL)
    *err = PCR_ERROR_WRITE;
  else
  {
    struct rsrc_section_size rs_size;
    rs_size = pcr_prepare_rsrc_data(pfile, err);
    
    pcr_update_section_table(pfile, rs_size);
    
    pcr_fwrite(&pfile->dos_header, sizeof(struct image_dos_header), 1, stream, err);
    
    unsigned int rm_stub_size = pfile->dos_header.e_lfanew - sizeof(struct image_dos_header);
    
    pcr_fwrite(pfile->rm_stub, rm_stub_size, 1, stream, err);
    pcr_fwrite(pfile->signature, sizeof(char), 4, stream, err); 
    pcr_fwrite(&pfile->image_file_header, sizeof(struct image_file_header), 1, stream, err);
    
    if (pfile->image_optional_header32 != NULL)
      pcr_fwrite(pfile->image_optional_header32, sizeof(struct image_optional_header32), 1, stream, err);
    
    pcr_fwrite(pfile->section_table, sizeof(struct image_section_header),
                pfile->image_file_header.number_of_sections, stream, err);
      
    pcr_write_section_data(pfile, stream, err, rs_size);
    
    fclose(stream);
  }
  
}

/**
 * 
 */
void pcr_write_section_data(struct pcr_file *pcr_file, FILE *stream, 
                            enum pcr_error *err_code, struct rsrc_section_size size)
{ 
  uint16_t i,num_sec;
  struct image_section_header *sec = NULL;
  
  if (*err_code != PCR_ERROR_NONE ||  pcr_file->image_optional_header32 == NULL)
    return;
  
  num_sec = pcr_file->image_file_header.number_of_sections;
  
  for (i=0; i<num_sec; i++)
  {
    sec = &pcr_file->section_table[i];
    
    printf("Write section %s: rva: 0x%X\n", sec->name, sec->virtual_adress);
    
    pcr_zero_pad(stream, sec->pointer_to_raw_data, err_code);
    
    if (strcmp(SECTION_NAME_RESOURCE, sec->name) == 0)
      pcr_write_rsrc_section(pcr_file, stream, err_code, size);
    else
      pcr_fwrite(pcr_file->section_data[i], sec->virtual_size, 1, stream, err_code);
  }
  
  // fill up until size of last section
  pcr_zero_pad(stream, sec->pointer_to_raw_data + sec->size_of_raw_data, err_code);
}

/**
 * 
 */
void pcr_write_rsrc_section(struct pcr_file *pcr_file, FILE *stream,
                            enum pcr_error *err_code, struct rsrc_section_size size)
{
  // write resource tree
  pcr_write_rsrc_node(pcr_file->rsrc_section_data->root_node, stream, err_code, size);
  pcr_write_data_description(pcr_file->rsrc_section_data->root_node, stream, err_code, size);
  pcr_write_directory_strings(pcr_file->rsrc_section_data->root_node, stream, err_code, size);
  pcr_write_rsrc_section_data(pcr_file->rsrc_section_data->root_node, stream, err_code, size);
  
}

/**
 * 
 */
void pcr_write_rsrc_node(struct resource_tree_node *node, FILE *stream, enum pcr_error *err_code, 
                         struct rsrc_section_size size)
{
  int i=0;
  
  if (node->resource_data != NULL)
    return;
  
  pcr_fwrite(&node->directory_table, sizeof(struct resource_directory_table), 1, stream, err_code);
  
  // write directory entries
  
  for (i=0; i<node->directory_table.number_of_name_entries; i++)
  {
    struct resource_tree_node *subnode = node->name_entries[i];
    
    // update name adress
    subnode->directory_entry.id += size.s_tree + size.s_data_description;
    subnode->directory_entry.id |= INT32_HIGH_BYTE;
    
    if (subnode->resource_data != NULL)
      subnode->directory_entry.rva += size.s_tree;
    
    pcr_fwrite(&subnode->directory_entry, sizeof(struct resource_directory_entry), 1, stream, err_code);
  }
    
  for (i=0; i<node->directory_table.number_of_id_entries; i++)
  {
    struct resource_tree_node *subnode = node->id_entries[i];
    
    if (subnode->resource_data != NULL)
      subnode->directory_entry.rva += size.s_tree;
    
    pcr_fwrite(&subnode->directory_entry, sizeof(struct resource_directory_entry), 1, stream, err_code);
  }
   
  // write subnodes
   
  for (i=0; i<node->directory_table.number_of_name_entries; i++)
    pcr_write_rsrc_node(node->name_entries[i], stream, err_code, size);
    
  for (i=0; i<node->directory_table.number_of_id_entries; i++)
    pcr_write_rsrc_node(node->id_entries[i], stream, err_code, size);
}

/**
 * recoursivly iterates the tree and writes data descriptions to the file
 */
void pcr_write_data_description(struct resource_tree_node *node, FILE *stream, enum pcr_error *err_code, 
                                struct rsrc_section_size size)
{
  if (node->resource_data != NULL) // write data description
  {
    struct resource_data_entry *entry = &node->resource_data->data_entry;
    
    entry->data_rva += size.section_start_pos + size.s_tree + size.s_data_description + size.s_directory_strings;
    
    pcr_fwrite(entry, sizeof(struct resource_data_entry), 1, stream, err_code);
  }
  else // go down if possible
  {
    int i=0;
    
    for (i=0; i<node->directory_table.number_of_name_entries; i++)
      pcr_write_data_description(node->name_entries[i], stream, err_code, size);
    
    for (i=0; i<node->directory_table.number_of_id_entries; i++)
      pcr_write_data_description(node->id_entries[i], stream, err_code, size);
  }
}

/**
 * writes node name identifiers
 */
void pcr_write_directory_strings(struct resource_tree_node *node, FILE *stream, enum pcr_error *err_code, 
                                 struct rsrc_section_size size)
{
  if (node->name != NULL)
  {
    pcr_write_string(node->name, stream, err_code);
  }
  
  int i=0;
  
  for (i=0; i<node->directory_table.number_of_name_entries; i++)
    pcr_write_directory_strings(node->name_entries[i], stream, err_code, size);
    
  for (i=0; i<node->directory_table.number_of_id_entries; i++)
    pcr_write_directory_strings(node->id_entries[i], stream, err_code, size);
}

/**
 * 
 */
void pcr_write_rsrc_section_data(struct resource_tree_node *node, FILE *stream, enum pcr_error *err_code, struct rsrc_section_size size)
{
  if (node->resource_data != NULL)
  {
    pcr_write_rsrc_data(node->resource_data, stream, err_code);
  }
  
  int i=0;
  for (i=0; i<node->directory_table.number_of_name_entries; i++)
    pcr_write_rsrc_section_data(node->name_entries[i], stream, err_code, size);
    
  for (i=0; i<node->directory_table.number_of_id_entries; i++)
    pcr_write_rsrc_section_data(node->id_entries[i], stream, err_code, size);
}

/**
 * 
 */
void pcr_write_rsrc_data(struct resource_data *str, FILE *stream, enum pcr_error *err_code)
{
  if (str != NULL)
  {
    if (str->type == RESOURCE_TYPE_STRINGS)
    {
      int i;
      for (i=0; i<str->number_of_strings; i++)
        pcr_write_string(str->strings[i], stream, err_code);
    }
    else
    {
      pcr_fwrite(str->raw_data, str->data_entry.size, 1, stream, err_code);
    }
  }
}

/**
 * 
 */
void pcr_write_string(struct rsrc_string *str, FILE *stream, enum pcr_error *err_code)
{
  int i;
  char null = 0;
  
  pcr_fwrite(&str->size, sizeof(uint16_t), 1, stream, err_code);
  
  for (i=0; i<str->size; i++)
  {
    pcr_fwrite(&str->str[i], sizeof(char), 1, stream, err_code);
    pcr_fwrite(&null, sizeof(char), 1, stream, err_code);
  }
}

/*
 * initialization functions
 */

void pcr_init_directory_table(struct resource_directory_table *table_ptr)
{
  table_ptr->number_of_id_entries = 0;
  table_ptr->number_of_name_entries = 0;
  table_ptr->characteristics = 0;
  table_ptr->major_version = 0;
  table_ptr->minor_version = 0;
  table_ptr->time_stamp = 0;
}

/*
 * free
 */

/**
 * 
 */
void pcr_free(struct pcr_file* pcr_file)
{
  if (pcr_file)
  {
  
    int i;
    for (i=0; i< pcr_file->image_file_header.number_of_sections; i++)
      free(pcr_file->section_data[i]);
    
    free(pcr_file->section_data);
    
    free(pcr_file->image_optional_header32);
    free(pcr_file->section_table);
    
    if (pcr_file->rsrc_section_data)
    {
      pcr_free_resource_tree_node(pcr_file->rsrc_section_data->root_node);
      free(pcr_file->rsrc_section_data);
    }
    
    free(pcr_file->rm_stub);
    
  }
  
  free(pcr_file);
    
}

/**
 * 
 */
void pcr_free_resource_tree_node(struct resource_tree_node *node)
{
  int i;
  
  if (node == NULL)
    return;
  
  for (i=0; i<node->directory_table.number_of_name_entries; i++)
    pcr_free_resource_tree_node(node->name_entries[i]);
  
  free(node->name_entries);
  
  for (i=0; i<node->directory_table.number_of_id_entries; i++)
    pcr_free_resource_tree_node(node->id_entries[i]);
  
  free(node->id_entries);
  
  pcr_free_resource_data(node->resource_data);
  
  pcr_free_resource_string(node->name);
  
  free(node);
  
}

/**
 * 
 */
void pcr_free_resource_data(struct resource_data *resource_data)
{
  if (resource_data != NULL)
  {
    int i;
    for (i=0; i<resource_data->number_of_strings; i++)
       pcr_free_resource_string(resource_data->strings[i]);
    
    free(resource_data->strings);
    free(resource_data->raw_data);
    free(resource_data);
  }
}

/**
 * 
 */
void pcr_free_resource_string(struct rsrc_string *str)
{
  if (str != NULL)
  {
    free(str->str);
    free(str);
  }
}

/*
 * access functions
 */

/**
 * Get section header by name. Returns NULL if not found.
 */
struct image_section_header * pcr_get_section_header(struct pcr_file *pfile, const char *name)
{
  int i;
  
  for (i=0; i<pfile->image_file_header.number_of_sections; i++)
    if (strcmp(name, pfile->section_table[i].name) == 0)
      return &pfile->section_table[i];
    
  return NULL;
}

/**
 * returns id node or NULL if unable to get it
 */
struct resource_tree_node* pcr_get_sub_id_node(const struct resource_tree_node *node, uint32_t id)
{
  struct resource_tree_node key, *kptr, **result = NULL;

  if (node && node->directory_table.number_of_id_entries > 0)
  {
    key.id = id;
    kptr = &key;
  
    result = (struct resource_tree_node **)bsearch(&kptr, node->id_entries, node->directory_table.number_of_id_entries, 
                  sizeof(struct resource_tree_node **), pcr_comp_id_tree_nodes);
  }
  
  if (result == NULL)
    return NULL;
  else
    return *result;
}

/**
 * returns name node or NULL if unable to get it
 */
struct resource_tree_node* pcr_get_sub_name_node(const struct resource_tree_node *node, const char *name)
{
  struct resource_tree_node key, *kptr, **result = NULL;
  pcr_error_code err = PCR_ERROR_NONE;
  
  if (node && node->directory_table.number_of_name_entries > 0)
  {
    key.name = (struct rsrc_string *)pcr_malloc(sizeof(struct rsrc_string), &err);
    key.name->str = (char *)pcr_malloc(strlen(name), &err);
    
    strcpy(key.name->str, name); 
    kptr = &key;
  
    result = (struct resource_tree_node **)bsearch(&kptr, node->name_entries, node->directory_table.number_of_name_entries, 
                  sizeof(struct resource_tree_node **), pcr_comp_name_tree_nodes);
    
    free(key.name->str);
    free(key.name);
  }
  
  if (result == NULL)
    return NULL;
  else
    return *result;
}

/**
 * Returns NULL if not found.
 */
struct resource_tree_node *pcr_get_rsrc_string_node_by_id(const struct pcr_file *file, uint32_t id)
{
  if (file == NULL)
  {
    printf("Resource file pointer is NULL!\n");
    return NULL;
  }
  
  struct resource_tree_node *string_dir;
  
  string_dir = pcr_get_sub_id_node(file->rsrc_section_data->root_node, RESOURCE_TYPE_STRINGS);
  
  return pcr_get_sub_id_node(string_dir, id);
}

/**
 * TODO error handling
 */
void pcr_add_rsrc_node(struct resource_tree_node *root, struct resource_tree_node *child)
{
  pcr_error_code err = PCR_ERROR_NONE;
  uint16_t num_id_entries;
  
  if (child->name == NULL)
  {
    printf("Add id node: %d\n", child->id);
    
    if (pcr_get_sub_id_node(root, child->id) != NULL)
      printf("Error: There is already a node with given id!\n");
    else
    {
      num_id_entries = root->directory_table.number_of_id_entries;
      num_id_entries ++;
      
      if (root->id_entries == NULL)
        printf("Root id null\n");
      
      struct resource_tree_node **id_entries_new = (struct resource_tree_node **)
        pcr_realloc(root->id_entries, num_id_entries * sizeof(struct resource_tree_node *), &err);
        
      if (id_entries_new == NULL)
        printf("Error: Realloc (pcr_add_rsrc_node)\n");
      else
      {
        root->id_entries = id_entries_new;
        root->directory_table.number_of_id_entries = num_id_entries;
        
        printf("NUm id entries (root) %d\n", num_id_entries);
        
        root->id_entries[num_id_entries - 1] = child;
        
        qsort(root->id_entries, num_id_entries, sizeof(struct resource_tree_node *),
              pcr_comp_id_tree_nodes);
        
      }
    }
  }
  else
  {
    printf("Warning: Adding named nodes is not supported yet!\n"); //TODO
  }
}

/**
 * 
 */
int32_t pcr_get_default_culture_id(struct pcr_file *pfile)
{
  struct culture_cnt {
    uint32_t id;
    uint32_t cnt;
  };

  int32_t default_culture = -1, default_c_cnt = 0;
  struct culture_cnt *c_counts = NULL, *c_ptr = NULL;
  uint32_t num_of_c = 0, i, j, k, c_id;
  
  struct resource_tree_node *root, *sub;
  
  if (pfile && 
      pfile->rsrc_section_data && 
      pfile->rsrc_section_data->root_node && 
      pcr_get_sub_id_node(pfile->rsrc_section_data->root_node, RESOURCE_TYPE_STRINGS))
  {
    root = pcr_get_sub_id_node(pfile->rsrc_section_data->root_node, RESOURCE_TYPE_STRINGS);
    
    for (i=0; i<root->directory_table.number_of_id_entries; i++)
    {
      sub = root->id_entries[i];
      
      for (j=0; j<sub->directory_table.number_of_id_entries; j++)
      {
        c_id = sub->id_entries[j]->id;
        
        for (k=0; k<num_of_c; k++)
          if (c_counts[k].id == c_id)
            c_ptr = &c_counts[k];
        
        if (c_ptr)
          c_ptr->cnt ++;
        else // add entry
        {
          num_of_c ++;
          c_counts = (struct culture_cnt *)realloc(c_counts, sizeof(struct culture_cnt) * num_of_c);
          
          c_counts[num_of_c - 1].id = c_id;
          c_counts[num_of_c - 1].cnt = 1;
        }
      } 
    }
    
    for (j=0; j<num_of_c; j++)
      if (default_c_cnt < c_counts[j].cnt)
        default_culture = c_counts[j].id;
  }
  
  return default_culture;
}

/**
 * 
 */
uint32_t pcr_get_default_codepage(struct pcr_file *pfile, uint32_t culture_id)
{
  struct resource_tree_node *version_node = NULL, *lang_node = NULL;
  uint32_t codepage = 0;
  
  if (pfile && pfile->rsrc_section_data && pfile->rsrc_section_data->root_node)
  {
    version_node = pcr_get_sub_id_node(pfile->rsrc_section_data->root_node, RESOURCE_TYPE_VERSION);
    version_node = pcr_get_sub_name_node(version_node, "VS_VERSION_INFO"); // TODO const
    
    lang_node = pcr_get_sub_id_node(version_node, culture_id);
    
    if (lang_node && lang_node->resource_data)
      codepage = lang_node->resource_data->data_entry.codepage;
  }
  
  return codepage;
}

//TODO
uint32_t pcr_get_rsrc_string_name_node(uint32_t string_id)
{
  return string_id/MAX_STRINGS_PER_LEAF + 1;
}

//TODO
uint32_t pcr_get_rsrc_data_string_index(uint32_t string_id)
{
  
  return 0;
}

/**
 * 
 */
pcr_string pcr_get_string(const struct pcr_file *file, uint32_t id, int32_t culture_id)
{
  pcr_string string;
  uint32_t resource_directory_id, offset, string_size;
  struct resource_tree_node *name_dir = NULL, *lang_dir = NULL;
  pcr_error_code err = PCR_ERROR_NONE;
  
  string.codepage = 0;
  string.value = NULL;
  string.size = 0;
  
  // calc ids
  resource_directory_id = id/MAX_STRINGS_PER_LEAF + 1;
  offset = id - (resource_directory_id-1) * MAX_STRINGS_PER_LEAF;
  
  name_dir = pcr_get_rsrc_string_node_by_id(file, resource_directory_id);
  
  if (name_dir)
  {
    if (culture_id == -1)
    {
      if (name_dir->directory_table.number_of_id_entries > 0)
        lang_dir = name_dir->id_entries[0];
    }
    else
      lang_dir = pcr_get_sub_id_node(name_dir, culture_id);
    
    if (lang_dir != NULL && lang_dir->resource_data != NULL &&
        offset < lang_dir->resource_data->number_of_strings)
    {
      string_size = lang_dir->resource_data->strings[offset]->size + 1;
      
      string.value = (char *)pcr_malloc(string_size * sizeof(char), &err);
      strncpy(string.value, lang_dir->resource_data->strings[offset]->str, string_size);
      
      string.size = string_size;
      string.codepage = lang_dir->resource_data->data_entry.codepage;
      
      printf("Debug: Found String: \"%s\"\n  rva: %d, offset: %d, language id: %d, codepage: %d\n", string.value, lang_dir->resource_data->data_entry.data_rva, 
            offset, lang_dir->id, lang_dir->resource_data->data_entry.codepage);
    }
  }
  
  if (string.value == NULL)
    printf("Debug: String not found! Id: %d, culture_id: %d\n", id, culture_id);
  
  return string;
}

/**
 * TODO
 */
pcr_error_code pcr_set_string(struct pcr_file *file, uint32_t id, uint32_t culture_id, const pcr_string pstr)
{
  pcr_error_code err = PCR_ERROR_NONE;
  uint32_t i;
  
  struct resource_tree_node *string_dir = NULL, *name_dir = NULL, *lang_dir = NULL;
  struct resource_data *resource_data = NULL;
  
  uint32_t resource_directory_id, offset;
  
  resource_directory_id = id/MAX_STRINGS_PER_LEAF + 1;   //TODO: move to a function
  offset = id - (resource_directory_id-1) * MAX_STRINGS_PER_LEAF;
  
  if (file->rsrc_section_data == NULL)
  {
    printf("ERROR: There is no resource section data!\n");
    return PCR_ERROR_UNSUPPORTED;
  }
  
  string_dir = pcr_get_sub_id_node(file->rsrc_section_data->root_node, RESOURCE_TYPE_STRINGS);
  
  if (string_dir == NULL)
  {
    printf("ERROR: There is no string type node!\n");
    return PCR_ERROR_UNSUPPORTED;
  }
  
  name_dir = pcr_get_sub_id_node(string_dir, resource_directory_id);
  
  if (name_dir == NULL) // create a new name node
  {
    printf("Debug: Trying to create a name node with id: %d\n", resource_directory_id);
    
    name_dir = (struct resource_tree_node *)pcr_malloc(sizeof(struct resource_tree_node), &err);
    
    name_dir->id = resource_directory_id;
    
    pcr_init_directory_table(&name_dir->directory_table);
    
    // TODO repeating code
    // ignore directory_entry, because it is only important at read/write
    name_dir->id_entries = NULL;
    name_dir->name_entries = NULL;
    name_dir->name = NULL;
    name_dir->resource_data = NULL;
    
    pcr_add_rsrc_node(string_dir, name_dir);
  }
  
  lang_dir = pcr_get_sub_id_node(name_dir, culture_id);
  
  if (lang_dir == NULL) // create a new language node
  {
    printf("Debug: Trying to create a language node with id: %d\n", culture_id);
    
    lang_dir = (struct resource_tree_node *)pcr_malloc(sizeof(struct resource_tree_node), &err);
    
    lang_dir->id = culture_id;
    
    pcr_init_directory_table(&lang_dir->directory_table);
    
    // ignore directory_entry, because it is only important at read/write
    lang_dir->id_entries = NULL;
    lang_dir->name_entries = NULL;
    lang_dir->name = NULL;
    lang_dir->resource_data = NULL;
    
    pcr_add_rsrc_node(name_dir, lang_dir);
  }
  
  resource_data = lang_dir->resource_data;
  
  if (resource_data == NULL)
  {
    printf("Debug: Trying to create resource data\n");
    
    resource_data = (struct resource_data *)pcr_malloc(sizeof(struct resource_data), &err);
    
    resource_data->type = RESOURCE_TYPE_STRINGS;
    resource_data->raw_data = NULL;
    
    resource_data->data_entry.codepage = pstr.codepage;
    resource_data->data_entry.data_rva = 0; 
    resource_data->data_entry.reserved = 0;
    resource_data->data_entry.size = MAX_STRINGS_PER_LEAF * 2; // sizeof(strings[i].size) * string count
  
    // create empty strings until offset is reached
    resource_data->strings = (struct rsrc_string **)pcr_malloc(sizeof(struct rsrc_string *) * MAX_STRINGS_PER_LEAF, &err);
    
    for (i=0; i<MAX_STRINGS_PER_LEAF; i++)
    {
      resource_data->strings[i] = (struct rsrc_string *)pcr_malloc(sizeof(struct rsrc_string), &err);
      resource_data->strings[i]->size = 0;
      resource_data->strings[i]->str = (char *)pcr_malloc(sizeof(char), &err);
      resource_data->strings[i]->str[0] = '\0';
    }
    
    resource_data->number_of_strings = MAX_STRINGS_PER_LEAF;
    
    lang_dir->resource_data = resource_data;
  }
  
  if (offset >= resource_data->number_of_strings)
  {
    printf("ERROR: offset  >= resource_data->number_of_strings)!!!\n");
    return PCR_ERROR_UNSUPPORTED;
  }
    
  
  // TODO refactor
  struct rsrc_string *r_str = NULL;
  
  r_str = lang_dir->resource_data->strings[offset];
  
  
  uint32_t len = pstr.size;
  int32_t len_diff = len - r_str->size;
  
  if (len == 0)
  {
    free(r_str->str);
    
    r_str->str = (char *)pcr_malloc(1, &err);
    r_str->str[0] = '\0';
  }
  else
  {
    if (r_str->str == NULL)
      r_str->str = (char *)pcr_malloc(len + 1, &err);
    else
      r_str->str = (char *)pcr_realloc(r_str->str, len + 1, &err); //TODO error!!
      
    strcpy(r_str->str, pstr.value);
  }
  
  r_str->size = len;
  lang_dir->resource_data->data_entry.size += (len_diff*2); // *2 word alignmend
  
  return err;
}
