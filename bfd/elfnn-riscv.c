/* RISC-V-specific support for NN-bit ELF.
   Copyright (C) 2011-2020 Free Software Foundation, Inc.

   Contributed by Andrew Waterman (andrew@sifive.com).
   Based on TILE-Gx and MIPS targets.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

/* This file handles RISC-V ELF targets.  */
#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "bfdlink.h"
#include "genlink.h"
#include "elf-bfd.h"
#include "elfxx-riscv.h"
#include "elf/riscv.h"
#include "opcode/riscv.h"
#include "objalloc.h"

/* Internal relocations used exclusively by the relaxation pass.  */
#define R_RISCV_DELETE (R_RISCV_max + 1)

#define ARCH_SIZE NN

#define MINUS_ONE ((bfd_vma)0 - 1)

#define RISCV_ELF_LOG_WORD_BYTES (ARCH_SIZE == 32 ? 2 : 3)

#define RISCV_ELF_WORD_BYTES (1 << RISCV_ELF_LOG_WORD_BYTES)

/* The name of the dynamic interpreter.  This is put in the .interp
   section.  */

#define ELF64_DYNAMIC_INTERPRETER "/lib/ld.so.1"
#define ELF32_DYNAMIC_INTERPRETER "/lib32/ld.so.1"

#define ELF_ARCH			bfd_arch_riscv
#define ELF_TARGET_ID			RISCV_ELF_DATA
#define ELF_MACHINE_CODE		EM_RISCV
#define ELF_MAXPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000

/* Constants for overlay system.  */
#define OVL_CRC_SZ            4
#define OVL_GROUPPAGESIZE     512
#define OVL_MAXGROUPSIZE      4096
#define OVL_FIRST_FREE_GROUP  1

/* RISC-V ELF linker hash entry.  */

struct riscv_elf_link_hash_entry
{
  struct elf_link_hash_entry elf;

  /* Track dynamic relocs copied for this symbol.  */
  struct elf_dyn_relocs *dyn_relocs;

#define GOT_UNKNOWN     0
#define GOT_NORMAL      1
#define GOT_TLS_GD      2
#define GOT_TLS_IE      4
#define GOT_TLS_LE      8
  char tls_type;

  /* Track whether this symbol needs an overlay PLT entry.  */
  int needs_ovlplt_entry;

  /* Track whether this symbols is referred to by an overlay relocation,
     and therefore needs to exist in at least one overlay group.  */
  int needs_overlay_group;

  /* Track whether this symbol is referred to by a non-overlay relocation.  */
  int non_overlay_reference;

  /* Track whether this symbol has already been handled and any
     overlay groups have already been generated.  */
  int overlay_groups_resolved;
};

#define riscv_elf_hash_entry(ent) \
  ((struct riscv_elf_link_hash_entry *)(ent))

struct _bfd_riscv_elf_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry.  */
  char *local_got_tls_type;
};

#define _bfd_riscv_elf_tdata(abfd) \
  ((struct _bfd_riscv_elf_obj_tdata *) (abfd)->tdata.any)

#define _bfd_riscv_elf_local_got_tls_type(abfd) \
  (_bfd_riscv_elf_tdata (abfd)->local_got_tls_type)

#define _bfd_riscv_elf_tls_type(abfd, h, symndx)		\
  (*((h) != NULL ? &riscv_elf_hash_entry (h)->tls_type		\
     : &_bfd_riscv_elf_local_got_tls_type (abfd) [symndx]))

#define is_riscv_elf(bfd)				\
  (bfd_get_flavour (bfd) == bfd_target_elf_flavour	\
   && elf_tdata (bfd) != NULL				\
   && elf_object_id (bfd) == RISCV_ELF_DATA)

#include "elf/common.h"
#include "elf/internal.h"

struct ovl_group_list_entry
{
  bfd_boolean is_initialized;

  int n_functions;
  const char **functions;

  /* Size of the groups contents, size of it when padded, and the offset
     to the start of the group in the .ovlgrps output section.  */
  bfd_vma group_size;
  bfd_vma padded_group_size;
  bfd_vma ovlgrpdata_offset;

  /* The calculated CRC for this function.  */
  unsigned int crc;

  /* The first and last functions allocated to this group.  */
  const char *first_func;
  const char *last_func;
};

struct ovl_group_list
{
  int n_groups;
  struct ovl_group_list_entry *groups;
};

struct riscv_elf_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *sdyntdata;

  /* Small local sym to section mapping cache.  */
  struct sym_cache sym_cache;

  /* The max alignment of output sections.  */
  bfd_vma max_alignment;

  /* Note whether linking overlay-enabled binary.  */
  bfd_boolean overlay_enabled;

  /* Short cut to overlay plt section.  */
  asection *sovlplt;
  /* Offset to the next free overlay plt entry.  */
  bfd_vma next_ovlplt_offset;

  /* Sizes for the group table and multigroup table, which will
     populate group 0.  */
  bfd_vma ovl_group_table_size;
  bfd_vma ovl_group_table_max_group;
  bfd_vma ovl_multigroup_table_size;

  /* Mappings from groups to functions and vice-versa.  */
  struct bfd_hash_table ovl_func_table;
  struct ovl_group_list ovl_group_list;
  bfd_boolean ovl_tables_populated;
};

/* A flag noting whether the gc mark and sweep pass has run, and therefore can
   reliably determine which functions should be treated as deleted.  */
static bfd_boolean comrv_use_gcmark = 0;

/* Get the RISC-V ELF linker hash table from a link_info structure.  */
#define riscv_elf_hash_table(p) \
  (elf_hash_table_id ((struct elf_link_hash_table *) ((p)->hash)) \
  == RISCV_ELF_DATA ? ((struct riscv_elf_link_hash_table *) ((p)->hash)) : NULL)

static bfd_boolean
riscv_info_to_howto_rela (bfd *abfd,
			  arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  cache_ptr->howto = riscv_elf_rtype_to_howto (abfd, ELFNN_R_TYPE (dst->r_info));
  return cache_ptr->howto != NULL;
}

static void
riscv_elf_append_rela (bfd *abfd, asection *s, Elf_Internal_Rela *rel)
{
  const struct elf_backend_data *bed;
  bfd_byte *loc;

  bed = get_elf_backend_data (abfd);
  loc = s->contents + (s->reloc_count++ * bed->s->sizeof_rela);
  bed->s->swap_reloca_out (abfd, rel, loc);
}

/* PLT/GOT stuff.  */

#define PLT_HEADER_INSNS 8
#define PLT_ENTRY_INSNS 4
#define PLT_HEADER_SIZE (PLT_HEADER_INSNS * 4)
#define PLT_ENTRY_SIZE (PLT_ENTRY_INSNS * 4)

#define OVLPLT_ENTRY_INSNS 3
#define OVLPLT_ENTRY_SIZE (OVLPLT_ENTRY_INSNS * 4)
#define OVLMULTIGROUP_ITEM_SIZE 4

#define GOT_ENTRY_SIZE RISCV_ELF_WORD_BYTES

#define GOTPLT_HEADER_SIZE (2 * GOT_ENTRY_SIZE)

#define sec_addr(sec) ((sec)->output_section->vma + (sec)->output_offset)

static bfd_vma
riscv_elf_got_plt_val (bfd_vma plt_index, struct bfd_link_info *info)
{
  return sec_addr (riscv_elf_hash_table (info)->elf.sgotplt)
	 + GOTPLT_HEADER_SIZE + (plt_index * GOT_ENTRY_SIZE);
}

#if ARCH_SIZE == 32
# define MATCH_LREG MATCH_LW
#else
# define MATCH_LREG MATCH_LD
#endif

/* Generate a PLT header.  */

static bfd_boolean
riscv_make_plt_header (bfd *output_bfd, bfd_vma gotplt_addr, bfd_vma addr,
		       uint32_t *entry)
{
  bfd_vma gotplt_offset_high = RISCV_PCREL_HIGH_PART (gotplt_addr, addr);
  bfd_vma gotplt_offset_low = RISCV_PCREL_LOW_PART (gotplt_addr, addr);

  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return FALSE;
    }

  /* auipc  t2, %hi(.got.plt)
     sub    t1, t1, t3		     # shifted .got.plt offset + hdr size + 12
     l[w|d] t3, %lo(.got.plt)(t2)    # _dl_runtime_resolve
     addi   t1, t1, -(hdr size + 12) # shifted .got.plt offset
     addi   t0, t2, %lo(.got.plt)    # &.got.plt
     srli   t1, t1, log2(16/PTRSIZE) # .got.plt offset
     l[w|d] t0, PTRSIZE(t0)	     # link map
     jr	    t3 */

  entry[0] = RISCV_UTYPE (AUIPC, X_T2, gotplt_offset_high);
  entry[1] = RISCV_RTYPE (SUB, X_T1, X_T1, X_T3);
  entry[2] = RISCV_ITYPE (LREG, X_T3, X_T2, gotplt_offset_low);
  entry[3] = RISCV_ITYPE (ADDI, X_T1, X_T1, -(PLT_HEADER_SIZE + 12));
  entry[4] = RISCV_ITYPE (ADDI, X_T0, X_T2, gotplt_offset_low);
  entry[5] = RISCV_ITYPE (SRLI, X_T1, X_T1, 4 - RISCV_ELF_LOG_WORD_BYTES);
  entry[6] = RISCV_ITYPE (LREG, X_T0, X_T0, RISCV_ELF_WORD_BYTES);
  entry[7] = RISCV_ITYPE (JALR, 0, X_T3, 0);

  return TRUE;
}

/* Generate a PLT entry.  */

static bfd_boolean
riscv_make_plt_entry (bfd *output_bfd, bfd_vma got, bfd_vma addr,
		      uint32_t *entry)
{
  /* RVE has no t3 register, so this won't work, and is not supported.  */
  if (elf_elfheader (output_bfd)->e_flags & EF_RISCV_RVE)
    {
      _bfd_error_handler (_("%pB: warning: RVE PLT generation not supported"),
			  output_bfd);
      return FALSE;
    }

  /* auipc  t3, %hi(.got.plt entry)
     l[w|d] t3, %lo(.got.plt entry)(t3)
     jalr   t1, t3
     nop */

  entry[0] = RISCV_UTYPE (AUIPC, X_T3, RISCV_PCREL_HIGH_PART (got, addr));
  entry[1] = RISCV_ITYPE (LREG,  X_T3, X_T3, RISCV_PCREL_LOW_PART (got, addr));
  entry[2] = RISCV_ITYPE (JALR, X_T1, X_T3, 0);
  entry[3] = RISCV_NOP;

  return TRUE;
}

/* Generate an overlay PLT entry.  */

static bfd_boolean
riscv_make_ovlplt_entry (bfd_vma addr, uint32_t *entry)
{
  /* lui   x30, %hi(.ovlplt entry)
     addi  x30, x30, %lo(.ovlplt entry)
     jalr  zero, x31, 0  */
  entry[0] = RISCV_UTYPE (LUI,  X_T5,
			  RISCV_CONST_HIGH_PART(addr));
  entry[1] = RISCV_ITYPE (ADDI, X_T5, X_T5,
			  RISCV_CONST_LOW_PART(addr));
  entry[2] = RISCV_ITYPE (JALR, X_ZERO, X_T6, 0);

  return TRUE;
}

/* Linked list of overlay group ids.
   NOTE: Offset will not change with relaxation, so this value MUST NOT be
         relied upon for token generation, use the output_offset instead.
   NOTE: processed_offset is used for mapfile generation and is calculated
         during the final link stage.  */
struct ovl_func_group_info
{
  bfd_vma id;
  bfd_vma unrelaxed_offset;
  bfd_vma processed_offset;
  struct ovl_func_group_info *next;
};

/* Hash entry storing the groups to which a function belongs.

   e.g. "FuncA,3,6,9" is stored as:

     entry->root.string = "FuncA"
     entry->root.hash   = hash("FuncA")
     entry->groups      = [3] -> [6] -> [9] -> NULL
     entry->multigroup  = TRUE
     entry->multigroup_offset = 0;
*/
struct ovl_func_hash_entry
{
  struct bfd_hash_entry root;
  /* List of groups to which the function belongs.  */
  struct ovl_func_group_info *groups;
  struct ovl_func_group_info *tail;
  /* TRUE if function belongs to more than one group.  */
  bfd_boolean multigroup;
  bfd_vma multigroup_offset;
  bfd_vma multigroup_token;
  /* PLT offset if this function has a PLT value.  */
  bfd_boolean plt_entry;
  bfd_vma plt_offset;
};

static struct ovl_group_list_entry *
ovl_group_list_newfunc (struct ovl_group_list *list, int group);

/* Retrieve or create a new entry in the overlay group list.  */
static struct ovl_group_list_entry *
ovl_group_list_lookup (struct ovl_group_list *ovl_group_list,
                       int group, bfd_boolean create)
{
  BFD_ASSERT (ovl_group_list);
  BFD_ASSERT (ovl_group_list->groups);

  if (group >= ovl_group_list->n_groups)
    {
      if (create)
	{
	  return ovl_group_list_newfunc (ovl_group_list, group);
	}
      else
	return NULL;
    }
  else
    {
      if (ovl_group_list->groups[group].is_initialized)
	{
	  return &ovl_group_list->groups[group];
	}
      else if (create)
	{
	  return ovl_group_list_newfunc (ovl_group_list, group);
	}
      else
	return NULL;
    }
}

static bfd_boolean
ovl_group_list_traverse (struct ovl_group_list *ovl_group_list,
                         bfd_boolean (*func) (struct ovl_group_list_entry *, int, void *),
                         void *info)
{
  bfd_boolean ret = TRUE;
  for (int i = 0; i < ovl_group_list->n_groups; i++)
    {
      struct ovl_group_list_entry *entry = &ovl_group_list->groups[i];
      if (entry->is_initialized)
        ret = func(entry, i, info);
      if (ret == FALSE)
        break;
    }
  return ret;
}

/* Look up an entry in an overlay grouping hash table.  */

#define ovl_func_hash_lookup(table, string, create, copy) \
  ((struct ovl_func_hash_entry *)                         \
   bfd_hash_lookup (table, (string), (create), (copy)))

/* Traverse an overlay group hash table.  */

#define ovl_func_hash_traverse(table, func, info)           \
  (bfd_hash_traverse                                              \
   (table,                                                        \
    (bfd_boolean (*) (struct bfd_hash_entry *, void *)) (func),   \
    (info)))

/* Create a new entry in an overlay grouping hash_table.  */
static struct bfd_hash_entry *
ovl_func_hash_newfunc (struct bfd_hash_entry *entry,
                       struct bfd_hash_table *table,
                       const char *string)
{
  struct ovl_func_hash_entry *ret = (struct ovl_func_hash_entry *) entry;

 /* Allocate the structure if it has not already been allocated by a
    derived class.  */
  if (ret == NULL)
    {
      ret = bfd_hash_allocate (table, sizeof (* ret));
      if (ret == NULL)
	return NULL;
    }

 /* Call the allocation method of the base class.  */
  ret = ((struct ovl_func_hash_entry *)
      bfd_hash_newfunc ((struct bfd_hash_entry *) ret, table, string));

  /* Initialize local fields.  */
  ret->groups = NULL;
  ret->tail = NULL;
  ret->multigroup = FALSE;
  ret->multigroup_offset = 0;

  return (struct bfd_hash_entry *) ret;
}

static struct ovl_group_list_entry *
ovl_group_list_newfunc (struct ovl_group_list *list, int group)
{
  BFD_ASSERT (list != NULL);
  BFD_ASSERT (list->groups != NULL);

  if (group >= list->n_groups)
    {
      list->groups = bfd_realloc (list->groups,
                                  sizeof (*list->groups) * (group+1));
      for ( ; list->n_groups < (group+1); list->n_groups++)
        list->groups[list->n_groups].is_initialized = FALSE;
    }
  else
    {
      BFD_ASSERT (!list->groups[group].is_initialized);
    }

  struct ovl_group_list_entry *ret = &list->groups[group];

  ret->n_functions = 0;
  ret->functions = NULL;
  ret->group_size = 0;
  ret->padded_group_size = 0;
  ret->ovlgrpdata_offset = 0;
  ret->first_func = NULL;
  ret->last_func = NULL;

  ret->is_initialized = TRUE;
  return ret;
}

/* Create a new overlay grouping hash table.  */

static bfd_boolean
ovl_func_hash_table_init (struct bfd_hash_table *table)
{
  bfd_hash_table_init (table, ovl_func_hash_newfunc,
		       sizeof (struct ovl_func_hash_entry));
  return TRUE;
}

static bfd_boolean
ovl_group_list_init (struct ovl_group_list *list)
{
  BFD_ASSERT (list != NULL);
  list->n_groups = 0;

  /* Allocate space for a single group even though there are none needed yet.
     This means bfd_realloc can be used unconditionally when new groups are
     added.  */
  list->groups = bfd_malloc(sizeof (*list->groups));
  return TRUE;
}

/* Print an entry from an overlay grouping list.  */
static bfd_boolean
print_group_list_entry (struct ovl_group_list_entry *entry, int index,
                              void *info ATTRIBUTE_UNUSED)
{
  fprintf (stderr, "Group %d", index);
  fprintf (stderr, " (output section offset: 0x%lx, size 0x%lx, padded size 0x%lx)",
           entry->ovlgrpdata_offset, entry->group_size,
           entry->padded_group_size);
  fputc (':', stderr);

  for (int i = 0; i < entry->n_functions; i++)
    fprintf (stderr, " %s", entry->functions[i]);
  fprintf (stderr, "\n");

  return TRUE;
}

/* Print each entry in a group to function list.  */
static void
print_group_list (struct ovl_group_list *list)
{
  ovl_group_list_traverse (list, print_group_list_entry, NULL);
}

/* Print an entry from an overlay grouping hash table.  */

static bfd_boolean
print_func_entry (struct ovl_func_hash_entry *entry,
                  void *info ATTRIBUTE_UNUSED)
{
  fprintf (stderr, "Function %s:", entry->root.string);
  struct ovl_func_group_info *head = entry->groups;
  while (head != NULL)
    {
			/* FIXME: Use relaxed offset if available.  */
      fprintf (stderr, " %lu (@%lu)", head->id, head->unrelaxed_offset);
      head = head->next;
    }
  fprintf(stderr, "\n");

  return TRUE;
}

/* Print each entry in an overlay grouping hash table.  */

static void
print_func_table (struct bfd_hash_table *table)
{
  ovl_func_hash_traverse (table, print_func_entry, NULL);
}

static bfd_boolean
ovl_update_func (struct bfd_hash_table *table,
		       const char *func, bfd_vma group)
{
  struct ovl_func_hash_entry *entry;
  struct ovl_func_group_info *this_node;

  entry = ovl_func_hash_lookup (table, func, TRUE, TRUE);
  if (entry == NULL)
    return FALSE;

  this_node =  objalloc_alloc ((struct objalloc *) table->memory,
				sizeof (struct ovl_func_group_info));
  this_node->id = group;
  this_node->unrelaxed_offset = 0;
  this_node->processed_offset = 0;
  this_node->next = NULL;

  if (entry->groups == NULL)
    entry->groups = this_node;
  else
    {
      entry->tail->next = this_node;
      entry->multigroup = TRUE;
      entry->multigroup_offset = 0;
    }
  entry->tail = this_node;

  return TRUE;
}

static bfd_boolean
ovl_update_group (struct ovl_group_list *list,
                  int group_id,
                  const char *func)
{
  struct ovl_group_list_entry *group_entry;

  /* Update the entry in the group list.  */
  group_entry = ovl_group_list_lookup (list, group_id, TRUE);
  if (group_entry == NULL)
    return FALSE;

  /* FIXME: When should this memory be freed?  */
  int n_functions = group_entry->n_functions + 1;
  if (group_entry->functions == NULL)
    {
      group_entry->functions =
	  bfd_malloc (n_functions * sizeof(*group_entry->functions));
    }
  else
    {
      group_entry->functions =
	  bfd_realloc (group_entry->functions,
	               n_functions * sizeof(*group_entry->functions));
    }
  /* Take a copy of the function name.  */
  char *func_name = bfd_malloc (strlen (func) + 1);
  strcpy (func_name, func);

  group_entry->functions[group_entry->n_functions] = func_name;
  group_entry->n_functions = n_functions;
  return TRUE;
}

/* For a function in the overlay grouping file, return whether this is a valid
   function, or whether it should be skipped (either because it doesn't exist,
   or GC sections has removed it.) If a function is being ignored, REASON is
   updated to provide a reason why.  */

static bfd_boolean
ovl_enable_grouping_for_func (const char *func, struct bfd_link_info *info,
			      char **reason)
{
  char *sec_name;
  bfd *ibfd;

  if (func == NULL)
    return FALSE;

  /* Search for a section for this symbol, and check whether the function
     has been deleted.  */
  sec_name = malloc(11 + strlen(func));
  sprintf (sec_name, ".ovlinput.%s", func);
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      asection *sec;

      if (! is_riscv_elf (ibfd))
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  if (strcmp(sec->name, sec_name) == 0)
	    {
              free(sec_name);
              /* If GC sections not in use, return TRUE to indicate found. */
	      if (!comrv_use_gcmark)
		return TRUE;
	      /* Otherwise return the GC Mark value */
	      if (sec->gc_mark == 1)
		return TRUE;
	      *reason = "section removed by gc-sections";
	      return FALSE;
	    }
	}
    }

  /* The function was not found, return FALSE to not create its entry.  */
  free (sec_name);
  *reason = "section not found";
  return FALSE;
}

/* Parse a line from the overlay grouping csv and insert into hash table.  */

static bfd_boolean
riscv_parse_grouping_line (char * line, struct bfd_hash_table *ovl_func_table,
			   struct ovl_group_list *ovl_group_list,
                           struct bfd_link_info *info)
{
  char *group_str, *endptr;
  char *func = NULL;
  char *reason = NULL;
  bfd_vma group;
  int group_cnt = 0;

  /* Parse function name.  */
  func = strtok (line, ",");

  /* Skip functions which have been garbage collected, they should not appear
     in any group.  */
  if (!ovl_enable_grouping_for_func (func, info, &reason))
    {
      if (func != NULL && reason != NULL)
        _bfd_error_handler (_("%pB: warning: Ignoring '%s' in overlay grouping "
                              "file: %s\n"), info->output_bfd, func, reason);
      return TRUE;
    }

  /* Parse group ids.  */
  while ((group_str = strtok (NULL, ",")) != NULL)
    {
      group = strtol (group_str, &endptr, 10);
      if (*endptr != 0)
	{
	  _bfd_error_handler (
	       _("Invalid group id \"%s\" in overlay grouping file"),
		 group_str);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      if (group == 0)
	{
	  _bfd_error_handler (
	      _("Invalid group id \"0\" in overlay grouping file"));
	  bfd_set_error (bfd_error_bad_value);
	}

      if (!ovl_update_func (ovl_func_table, func, group))
	{
	  _bfd_error_handler (_("Failed to add %s to ovl_func_table"), func);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      if (!ovl_update_group (ovl_group_list, group, func))
	{
	  _bfd_error_handler (_("Failed to add %s to ovl_group_list"),
			      group_str);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      group_cnt++;
    }

  if (group_cnt == 0)
    {
     _bfd_error_handler (_("No groups found for %s in overlay grouping file"),
			 func);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  return TRUE;
}

/* Parse a csv containg grouping information for each function.  */

static bfd_boolean
parse_grouping_file (FILE * f,
                     struct bfd_hash_table *ovl_func_table,
                     struct ovl_group_list *ovl_group_list,
		     struct bfd_link_info *info)
{
  int c;
  int i = 0;
  int BUFSIZE = 1024;
  char *line = bfd_malloc (BUFSIZE);
  bfd_boolean lines_parsed_p = FALSE;

  while (1)
    {
      c = fgetc (f);

      if (i >= BUFSIZE)
	{
	  /* Line too long for buffer, increase buffer size.  */
	  BUFSIZE *= 2;
	  line = bfd_realloc (line, BUFSIZE);
	}

      if (c == '\n' || c == '\r' || c == EOF)
	{
	  /* Parse line if not blank.  */
	  if (i > 0)
	    {
	      line[i++] = '\0';
	      if (!riscv_parse_grouping_line (line, ovl_func_table,
					      ovl_group_list, info))
	        {
		  free(line);
		  return FALSE;
		}
	      else
		lines_parsed_p = TRUE;
	      /* Line parsed, goto start of buffer.  */
	      i=0;
	    }
	  if (c == EOF)
	    break;
	}
      else
	line[i++] = c;
    }

  if (!lines_parsed_p)
    {
      _bfd_error_handler ("No lines found in grouping file");
      bfd_set_error (bfd_error_bad_value);
    }

  free (line);
  return lines_parsed_p;
}

/* Store grouping info in a hash table.  */

static bfd_boolean
create_ovl_group_table (struct bfd_hash_table *ovl_func_table,
                        struct ovl_group_list *ovl_group_list,
                        bfd_boolean *ovl_tables_populated)
{
  bfd_boolean ret;
  *ovl_tables_populated = FALSE;

  ret = ovl_func_hash_table_init (ovl_func_table);
  if (!ret)
    {
      _bfd_error_handler (_("Failed to initialize ovl_func_table table"));
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  ret = ovl_group_list_init (ovl_group_list);
  if (!ret)
    {
      _bfd_error_handler (_("Failed to initialize ovl_group_list"));
      bfd_set_error (bfd_error_bad_value);
      //ovl_group_list_free (ovl_group_list);
      return FALSE;
    }

  return ret;
}

/* Build a version of the current ovl section based on what is currently loaded.  */
static bfd_boolean
build_current_ovl_section (struct bfd_link_info *info, void **data)
{
  bfd *output_bfd = info->output_bfd;
  asection *sec = bfd_get_section_by_name (output_bfd, ".ovlgrps");
  BFD_ASSERT (sec != NULL);

  /* Nasty hack: When the .ovlgrps output section is created it
     is created with its flags initialized to the same flags as the
     last constituent input section. Because the last input section
     is a dynamic section, the output section erroneously picks up the
     SEC_IN_MEMORY flag which causes bfd_get_section_contents to
     fail when it tries to read from the "contents" of .ovlgrps.  */
  sec->flags &= ~SEC_IN_MEMORY;

  void *section_data = malloc(sec->size);
  BFD_ASSERT (section_data != NULL);
  *data = section_data;
  /* Start by loading the entire contents of this section, this will cover non
     dynamic sections.  */
  bfd_boolean res = bfd_get_section_contents (output_bfd, sec, section_data, 0, sec->size);
  BFD_ASSERT(res == TRUE);

  /* Look at all the input sections, if the output section matches this, then
     load the contents into that section.  */
  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
  {
    asection *isec;
    for (isec = ibfd->sections; isec != NULL; isec = isec->next)
    {
      if (isec->contents != NULL && isec->output_section == sec)
      {
	memcpy (section_data + isec->output_offset, isec->contents, isec->size);
      }
    }
  }

  return TRUE;
}

/* TODO: Integrate this file (if appropriate)  */
#include "elfnn-riscv-crc.inc"

/* FIXME: Pass this along.  */
static void *ovl_cached_data = NULL;

static bfd_boolean
emit_ovl_padding_and_crc_entry (struct ovl_group_list_entry *entry,
                                int group, void *data)
{
  if (riscv_comrv_debug)
    fprintf (stderr, "Group %d*: ", group);

  if (entry->group_size == 0)
    {
      if (riscv_comrv_debug)
	fprintf(stderr, "(empty, skipping)\n");
      return TRUE;
    }

  BFD_ASSERT(ovl_cached_data != NULL);

  /* Load the padding section.  */
  char group_sec_name[40];
  sprintf (group_sec_name, ".ovlinput.__internal.padding.%u", group);
  struct bfd_link_info *info = data;
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  asection *padding_sec = bfd_get_section_by_name (htab->elf.dynobj, group_sec_name);
  BFD_ASSERT(padding_sec != NULL);

  /* Emit the padding into the padding section. This is copied to the cached
     data so a CRC can be run over the entire block in one pass.  */
  for (bfd_vma offs = 0; offs < padding_sec->size; offs += 2)
    bfd_put_16 (htab->elf.dynobj, group, padding_sec->contents + offs);
  memcpy (ovl_cached_data + padding_sec->output_offset, padding_sec->contents,
          padding_sec->size);

  /* Calculate the CRC of the group.  */
  unsigned int crc;

  /* This shouldn't happen, except in the case of something going wrong
     previously. Warn if this is the case.  */
  BFD_ASSERT((entry->ovlgrpdata_offset + entry->padded_group_size) ==
      (padding_sec->output_offset + padding_sec->size));
  if ((entry->ovlgrpdata_offset + entry->padded_group_size) !=
      (padding_sec->output_offset + padding_sec->size))
    crc = 0;
  else
    crc = xcrc32_custom(ovl_cached_data + entry->ovlgrpdata_offset,
			entry->padded_group_size - OVL_CRC_SZ,
			riscv_crc_init, riscv_crc_poly, riscv_crc_xorout,
			riscv_crc_refin, riscv_crc_refout);

  /* Put the 32-bit CRC at the end after the padding.  */
  bfd_put_32 (info->output_bfd, crc,
              padding_sec->contents + padding_sec->size - OVL_CRC_SZ);

  /* Store the CRC for printing in the mapfile.  */
  entry->crc = crc;

  if (riscv_comrv_debug)
    fprintf(stderr, "%x\n", crc);
  return TRUE;
}

/* Calculate and insert all overlay group sections CRC values.  */
static void
emit_ovl_padding_and_crc (struct ovl_group_list *list,
                          struct bfd_link_info *info)
{
  if (riscv_comrv_debug)
    fprintf(stderr, "Calculating CRCs\n================\n");

  build_current_ovl_section (info, &ovl_cached_data);
  BFD_ASSERT(ovl_cached_data != NULL);
  ovl_group_list_traverse (list, emit_ovl_padding_and_crc_entry, info);
  free(ovl_cached_data);
}

/* Create an entry in an RISC-V ELF linker hash table.  */

static struct bfd_hash_entry *
link_hash_newfunc (struct bfd_hash_entry *entry,
		   struct bfd_hash_table *table, const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry =
          bfd_hash_allocate (table,
                             sizeof (struct riscv_elf_link_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = _bfd_elf_link_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct riscv_elf_link_hash_entry *eh;

      eh = (struct riscv_elf_link_hash_entry *) entry;
      eh->dyn_relocs = NULL;
      eh->tls_type = GOT_UNKNOWN;
      eh->needs_ovlplt_entry = FALSE;
      eh->needs_overlay_group = FALSE;
      eh->non_overlay_reference = FALSE;
      eh->overlay_groups_resolved = FALSE;
    }

  return entry;
}

/* Create a RISC-V ELF linker hash table.  */

static struct bfd_link_hash_table *
riscv_elf_link_hash_table_create (bfd *abfd)
{
  struct riscv_elf_link_hash_table *ret;
  size_t amt = sizeof (struct riscv_elf_link_hash_table);

  ret = (struct riscv_elf_link_hash_table *) bfd_zmalloc (amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->elf, abfd, link_hash_newfunc,
				      sizeof (struct riscv_elf_link_hash_entry),
				      RISCV_ELF_DATA))
    {
      free (ret);
      return NULL;
    }

  ret->max_alignment = (bfd_vma) -1;

  ret->sovlplt = NULL;
  ret->next_ovlplt_offset = 0;

  ret->ovl_group_table_size = 0;
  ret->ovl_group_table_max_group = 0;
  ret->ovl_multigroup_table_size = 0;

  bfd_boolean success;
  success = create_ovl_group_table (&ret->ovl_func_table, &ret->ovl_group_list,
                                    &ret->ovl_tables_populated);
  if (success)
    {
      if (riscv_comrv_debug)
	{
	  print_group_list (&ret->ovl_group_list);
	  print_func_table (&ret->ovl_func_table);
	}
    }
  else
    return NULL;

  return &ret->elf.root;
}

/* Create the .ovlplt section, and .rela.ovlplt.  */

static bfd_boolean
riscv_elf_create_ovlplt_section (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  asection *s;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);

  /* This function may be called more than once.  */
  if (htab->sovlplt != NULL)
    return TRUE;

  flags = bed->dynamic_sec_flags | SEC_READONLY | SEC_CODE;

  s = bfd_make_section_anyway_with_flags (abfd, ".ovlplt", flags);
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return FALSE;
  /* The size of the overlay plt section is calculated later.  */
  s->size = 0;
  htab->sovlplt = s;

  return TRUE;
}

/* Create the .got section.  */

static bfd_boolean
riscv_elf_create_got_section (bfd *abfd, struct bfd_link_info *info)
{
  flagword flags;
  asection *s, *s_got;
  struct elf_link_hash_entry *h;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_link_hash_table *htab = elf_hash_table (info);

  /* This function may be called more than once.  */
  if (htab->sgot != NULL)
    return TRUE;

  flags = bed->dynamic_sec_flags;

  s = bfd_make_section_anyway_with_flags (abfd,
					  (bed->rela_plts_and_copies_p
					   ? ".rela.got" : ".rel.got"),
					  (bed->dynamic_sec_flags
					   | SEC_READONLY));
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return FALSE;
  htab->srelgot = s;

  s = s_got = bfd_make_section_anyway_with_flags (abfd, ".got", flags);
  if (s == NULL
      || !bfd_set_section_alignment (s, bed->s->log_file_align))
    return FALSE;
  htab->sgot = s;

  /* The first bit of the global offset table is the header.  */
  s->size += bed->got_header_size;

  if (bed->want_got_plt)
    {
      s = bfd_make_section_anyway_with_flags (abfd, ".got.plt", flags);
      if (s == NULL
	  || !bfd_set_section_alignment (s, bed->s->log_file_align))
	return FALSE;
      htab->sgotplt = s;

      /* Reserve room for the header.  */
      s->size += GOTPLT_HEADER_SIZE;
    }

  if (bed->want_got_sym)
    {
      /* Define the symbol _GLOBAL_OFFSET_TABLE_ at the start of the .got
	 section.  We don't do this in the linker script because we don't want
	 to define the symbol if we are not creating a global offset
	 table.  */
      h = _bfd_elf_define_linkage_sym (abfd, info, s_got,
				       "_GLOBAL_OFFSET_TABLE_");
      elf_hash_table (info)->hgot = h;
      if (h == NULL)
	return FALSE;
    }

  return TRUE;
}

/* Create .plt, .rela.plt, .got, .got.plt, .rela.got, .dynbss, and
   .rela.bss sections in DYNOBJ, and set up shortcuts to them in our
   hash table.  */

static bfd_boolean
riscv_elf_create_dynamic_sections (bfd *dynobj,
				   struct bfd_link_info *info)
{
  if (riscv_comrv_debug)
    fprintf(stderr, "* riscv_elf_create_dynamic_sections\n");
  struct riscv_elf_link_hash_table *htab;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (!riscv_elf_create_got_section (dynobj, info))
    return FALSE;

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;

  if (!bfd_link_pic (info))
    {
      /* Technically, this section doesn't have contents.  It is used as the
	 target of TLS copy relocs, to copy TLS data from shared libraries into
	 the executable.  However, if we don't mark it as loadable, then it
	 matches the IS_TBSS test in ldlang.c, and there is no run-time address
	 space allocated for it even though it has SEC_ALLOC.  That test is
	 correct for .tbss, but not correct for this section.  There is also
	 a second problem that having a section with no contents can only work
	 if it comes after all sections with contents in the same segment,
	 but the linker script does not guarantee that.  This is just mixed in
	 with other .tdata.* sections.  We can fix both problems by lying and
	 saying that there are contents.  This section is expected to be small
	 so this should not cause a significant extra program startup cost.  */
      htab->sdyntdata =
	bfd_make_section_anyway_with_flags (dynobj, ".tdata.dyn",
					    (SEC_ALLOC | SEC_THREAD_LOCAL
					     | SEC_LOAD | SEC_DATA
					     | SEC_HAS_CONTENTS
					     | SEC_LINKER_CREATED));
    }

  if (!htab->elf.splt || !htab->elf.srelplt || !htab->elf.sdynbss
      || (!bfd_link_pic (info) && (!htab->elf.srelbss || !htab->sdyntdata)))
    abort ();

  return TRUE;
}

/* Copy the extra info we tack onto an elf_link_hash_entry.  */

static void
riscv_elf_copy_indirect_symbol (struct bfd_link_info *info,
				struct elf_link_hash_entry *dir,
				struct elf_link_hash_entry *ind)
{
  struct riscv_elf_link_hash_entry *edir, *eind;

  edir = (struct riscv_elf_link_hash_entry *) dir;
  eind = (struct riscv_elf_link_hash_entry *) ind;

  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
	{
	  struct elf_dyn_relocs **pp;
	  struct elf_dyn_relocs *p;

	  /* Add reloc counts against the indirect sym to the direct sym
	     list.  Merge any entries against the same section.  */
	  for (pp = &eind->dyn_relocs; (p = *pp) != NULL; )
	    {
	      struct elf_dyn_relocs *q;

	      for (q = edir->dyn_relocs; q != NULL; q = q->next)
		if (q->sec == p->sec)
		  {
		    q->pc_count += p->pc_count;
		    q->count += p->count;
		    *pp = p->next;
		    break;
		  }
	      if (q == NULL)
		pp = &p->next;
	    }
	  *pp = edir->dyn_relocs;
	}

      edir->dyn_relocs = eind->dyn_relocs;
      eind->dyn_relocs = NULL;
    }

  if (ind->root.type == bfd_link_hash_indirect
      && dir->got.refcount <= 0)
    {
      edir->tls_type = eind->tls_type;
      eind->tls_type = GOT_UNKNOWN;
    }
  _bfd_elf_link_hash_copy_indirect (info, dir, ind);
}

static bfd_boolean
riscv_elf_record_tls_type (bfd *abfd, struct elf_link_hash_entry *h,
			   unsigned long symndx, char tls_type)
{
  char *new_tls_type = &_bfd_riscv_elf_tls_type (abfd, h, symndx);

  *new_tls_type |= tls_type;
  if ((*new_tls_type & GOT_NORMAL) && (*new_tls_type & ~GOT_NORMAL))
    {
      (*_bfd_error_handler)
	(_("%pB: `%s' accessed both as normal and thread local symbol"),
	 abfd, h ? h->root.root.string : "<local>");
      return FALSE;
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_record_got_reference (bfd *abfd, struct bfd_link_info *info,
				struct elf_link_hash_entry *h, long symndx)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;

  if (htab->elf.sgot == NULL)
    {
      if (!riscv_elf_create_got_section (htab->elf.dynobj, info))
	return FALSE;
    }

  if (h != NULL)
    {
      h->got.refcount += 1;
      return TRUE;
    }

  /* This is a global offset table entry for a local symbol.  */
  if (elf_local_got_refcounts (abfd) == NULL)
    {
      bfd_size_type size = symtab_hdr->sh_info * (sizeof (bfd_vma) + 1);
      if (!(elf_local_got_refcounts (abfd) = bfd_zalloc (abfd, size)))
	return FALSE;
      _bfd_riscv_elf_local_got_tls_type (abfd)
	= (char *) (elf_local_got_refcounts (abfd) + symtab_hdr->sh_info);
    }
  elf_local_got_refcounts (abfd) [symndx] += 1;

  return TRUE;
}

/* Look at all sections in ABFD and enable overlay support if any contain
   overlay functions/data.  */
static bfd_boolean
riscv_elf_check_sections (bfd *abfd, struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab;
  asection *sec;

  if (bfd_link_relocatable (info))
    return TRUE;

  htab = riscv_elf_hash_table (info);

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  for (sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      /* If this is an overlay input section, flag the link as being overlay
         enabled. */
      if (strncmp(sec->name, ".ovlinput.", strlen(".ovlinput.")) == 0)
        {
          info->dynamic = 1;
          htab->overlay_enabled = 1;
        }
    }

  return TRUE;
}

static bfd_boolean
bad_static_reloc (bfd *abfd, unsigned r_type, struct elf_link_hash_entry *h)
{
  reloc_howto_type * r = riscv_elf_rtype_to_howto (abfd, r_type);

  (*_bfd_error_handler)
    (_("%pB: relocation %s against `%s' can not be used when making a shared "
       "object; recompile with -fPIC"),
     abfd, r ? r->name : _("<unknown>"),
     h != NULL ? h->root.root.string : "a local symbol");
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}
/* Look through the relocs for a section during the first phase, and
   allocate space in the global offset table or procedure linkage
   table.  */

static bfd_boolean
riscv_elf_check_relocs (bfd *abfd, struct bfd_link_info *info,
			asection *sec, const Elf_Internal_Rela *relocs)
{
  struct riscv_elf_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  asection *sreloc = NULL;

  if (bfd_link_relocatable (info))
    return TRUE;

  htab = riscv_elf_hash_table (info);
  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  if (htab->elf.dynobj == NULL)
    htab->elf.dynobj = abfd;

  for (rel = relocs; rel < relocs + sec->reloc_count; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h;

      r_symndx = ELFNN_R_SYM (rel->r_info);
      r_type = ELFNN_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  (*_bfd_error_handler) (_("%pB: bad symbol index: %d"),
				 abfd, r_symndx);
	  return FALSE;
	}

      if (r_symndx < symtab_hdr->sh_info)
	h = NULL;
      else
	{
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      switch (r_type)
	{
	case R_RISCV_OVLPLT_LO12_I:
	case R_RISCV_OVLPLT_HI20:
	case R_RISCV_OVLPLT32:
	  /* Create the overlay PLT section if it doesn't already exist.  */
	  if (!htab->sovlplt)
	    {
	      if (!riscv_elf_create_ovlplt_section (htab->elf.dynobj, info))
		return FALSE;
	      /* Enables analysis of dynamic sections. This is needed so
	         that we can resize the overlay PLT section after we
	         know how many entries will be needed.  */
	      info->dynamic = 1;
	    }

	  {
	    struct riscv_elf_link_hash_entry *eh =
		(struct riscv_elf_link_hash_entry *) h;
	    if (eh && !eh->needs_ovlplt_entry) 
	      {
		eh->needs_ovlplt_entry = TRUE;
		htab->sovlplt->size += OVLPLT_ENTRY_SIZE;
	      }
	  }
	  /* fallthrough */

	case R_RISCV_OVL_LO12_I:
	case R_RISCV_OVL_HI20:
	case R_RISCV_OVL32:
	  /* Enable analysis of dynamic sections since the size of the
	     created sections needs to be calculated later.  */
	  info->dynamic = 1;
          htab->overlay_enabled = 1;
	  {
	    struct riscv_elf_link_hash_entry *eh =
		(struct riscv_elf_link_hash_entry *) h;

	    /* This symbol must exist in an overlay group.  */
	    if (eh)
	      eh->needs_overlay_group = TRUE;
	  }
	  break;

	case R_RISCV_TLS_GD_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_GD))
	    return FALSE;
	  break;

	case R_RISCV_TLS_GOT_HI20:
	  if (bfd_link_pic (info))
	    info->flags |= DF_STATIC_TLS;
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_IE))
	    return FALSE;
	  break;

	case R_RISCV_GOT_HI20:
	  if (!riscv_elf_record_got_reference (abfd, info, h, r_symndx)
	      || !riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_NORMAL))
	    return FALSE;
	  break;

	case R_RISCV_CALL_PLT:
	  /* This symbol requires a procedure linkage table entry.  We
	     actually build the entry in adjust_dynamic_symbol,
	     because this might be a case of linking PIC code without
	     linking in any dynamic objects, in which case we don't
	     need to generate a procedure linkage table after all.  */

	  if (h != NULL)
	    {
	      h->needs_plt = 1;
	      h->plt.refcount += 1;

	      /* Note that this symbol as a non-overlay function.  */
	      struct riscv_elf_link_hash_entry *eh =
		  (struct riscv_elf_link_hash_entry *)h;
	      eh->non_overlay_reference = TRUE;
	    }
	  break;

	case R_RISCV_CALL:
	  if (h != NULL)
	    {
	      /* Note that this symbol as a non-overlay function.  */
	      struct riscv_elf_link_hash_entry *eh =
		  (struct riscv_elf_link_hash_entry *)h;
	      eh->non_overlay_reference = TRUE;
	    }
	  // fallthrough

	case R_RISCV_JAL:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_JUMP:
	case R_RISCV_PCREL_HI20:
	  /* In shared libraries, these relocs are known to bind locally.  */
	  if (bfd_link_pic (info))
	    break;
	  goto static_reloc;

	case R_RISCV_TPREL_HI20:
	  if (!bfd_link_executable (info))
	    return bad_static_reloc (abfd, r_type, h);
	  if (h != NULL)
	    riscv_elf_record_tls_type (abfd, h, r_symndx, GOT_TLS_LE);
	  goto static_reloc;

	case R_RISCV_HI20:
	  if (bfd_link_pic (info))
	    return bad_static_reloc (abfd, r_type, h);
	  /* Fall through.  */

	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	case R_RISCV_64:
	case R_RISCV_32:
	  /* Fall through.  */

	static_reloc:
	  /* This reloc might not bind locally.  */
	  if (h != NULL)
	    h->non_got_ref = 1;

	  if (h != NULL && !bfd_link_pic (info))
	    {
	      /* We may need a .plt entry if the function this reloc
		 refers to is in a shared lib.  */
	      h->plt.refcount += 1;
	    }

	  /* If we are creating a shared library, and this is a reloc
	     against a global symbol, or a non PC relative reloc
	     against a local symbol, then we need to copy the reloc
	     into the shared library.  However, if we are linking with
	     -Bsymbolic, we do not need to copy a reloc against a
	     global symbol which is defined in an object we are
	     including in the link (i.e., DEF_REGULAR is set).  At
	     this point we have not seen all the input files, so it is
	     possible that DEF_REGULAR is not set now but will be set
	     later (it is never cleared).  In case of a weak definition,
	     DEF_REGULAR may be cleared later by a strong definition in
	     a shared library.  We account for that possibility below by
	     storing information in the relocs_copied field of the hash
	     table entry.  A similar situation occurs when creating
	     shared libraries and symbol visibility changes render the
	     symbol local.

	     If on the other hand, we are creating an executable, we
	     may need to keep relocations for symbols satisfied by a
	     dynamic library if we manage to avoid copy relocs for the
	     symbol.  */
	  reloc_howto_type * r = riscv_elf_rtype_to_howto (abfd, r_type);

	  if ((bfd_link_pic (info)
	       && (sec->flags & SEC_ALLOC) != 0
	       && ((r != NULL && ! r->pc_relative)
		   || (h != NULL
		       && (! info->symbolic
			   || h->root.type == bfd_link_hash_defweak
			   || !h->def_regular))))
	      || (!bfd_link_pic (info)
		  && (sec->flags & SEC_ALLOC) != 0
		  && h != NULL
		  && (h->root.type == bfd_link_hash_defweak
		      || !h->def_regular)))
	    {
	      struct elf_dyn_relocs *p;
	      struct elf_dyn_relocs **head;

	      /* When creating a shared object, we must copy these
		 relocs into the output file.  We create a reloc
		 section in dynobj and make room for the reloc.  */
	      if (sreloc == NULL)
		{
		  sreloc = _bfd_elf_make_dynamic_reloc_section
		    (sec, htab->elf.dynobj, RISCV_ELF_LOG_WORD_BYTES,
		    abfd, /*rela?*/ TRUE);

		  if (sreloc == NULL)
		    return FALSE;
		}

	      /* If this is a global symbol, we count the number of
		 relocations we need for this symbol.  */
	      if (h != NULL)
		head = &((struct riscv_elf_link_hash_entry *) h)->dyn_relocs;
	      else
		{
		  /* Track dynamic relocs needed for local syms too.
		     We really need local syms available to do this
		     easily.  Oh well.  */

		  asection *s;
		  void *vpp;
		  Elf_Internal_Sym *isym;

		  isym = bfd_sym_from_r_symndx (&htab->sym_cache,
						abfd, r_symndx);
		  if (isym == NULL)
		    return FALSE;

		  s = bfd_section_from_elf_index (abfd, isym->st_shndx);
		  if (s == NULL)
		    s = sec;

		  vpp = &elf_section_data (s)->local_dynrel;
		  head = (struct elf_dyn_relocs **) vpp;
		}

	      p = *head;
	      if (p == NULL || p->sec != sec)
		{
		  size_t amt = sizeof *p;
		  p = ((struct elf_dyn_relocs *)
		       bfd_alloc (htab->elf.dynobj, amt));
		  if (p == NULL)
		    return FALSE;
		  p->next = *head;
		  *head = p;
		  p->sec = sec;
		  p->count = 0;
		  p->pc_count = 0;
		}

	      p->count += 1;
	      p->pc_count += r == NULL ? 0 : r->pc_relative;
	    }

	  break;

	case R_RISCV_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    return FALSE;
	  break;

	case R_RISCV_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    return FALSE;
	  break;

	default:
	  break;
	}

      if (h)
	{
	  struct riscv_elf_link_hash_entry *eh =
	      (struct riscv_elf_link_hash_entry *)h;
	  if (eh->needs_overlay_group && eh->non_overlay_reference)
	    {
	      (*_bfd_error_handler) (_("%pB: Symbol '%s` referred to by both "
	                               "overlay and non-overlay relocations"),
	                             abfd, h->root.root.string);
	      return FALSE;
	    }
	}
    }

  return TRUE;
}

static asection *
riscv_elf_gc_mark_hook (asection *sec,
			struct bfd_link_info *info,
			Elf_Internal_Rela *rel,
			struct elf_link_hash_entry *h,
			Elf_Internal_Sym *sym)
{
  /* Note that gc-sections has been used, allowing some ComRV table generation
     to be skipped for dead functions (i.e. sec->gc_mark is reliable).  */
  comrv_use_gcmark = 1;

  if (h != NULL)
    switch (ELFNN_R_TYPE (rel->r_info))
      {
      case R_RISCV_GNU_VTINHERIT:
      case R_RISCV_GNU_VTENTRY:
	return NULL;
      }

  return _bfd_elf_gc_mark_hook (sec, info, rel, h, sym);
}

/* Find dynamic relocs for H that apply to read-only sections.  */

static asection *
readonly_dynrelocs (struct elf_link_hash_entry *h)
{
  struct elf_dyn_relocs *p;

  for (p = riscv_elf_hash_entry (h)->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec->output_section;

      if (s != NULL && (s->flags & SEC_READONLY) != 0)
	return p->sec;
    }
  return NULL;
}

/* Adjust a symbol defined by a dynamic object and referenced by a
   regular object.  The current definition is in some section of the
   dynamic object, but we're not including those sections.  We have to
   change the definition to something the rest of the link can
   understand.  */

static bfd_boolean
riscv_elf_adjust_dynamic_symbol (struct bfd_link_info *info,
				 struct elf_link_hash_entry *h)
{
  struct riscv_elf_link_hash_table *htab;
  struct riscv_elf_link_hash_entry * eh;
  bfd *dynobj;
  asection *s, *srel;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  dynobj = htab->elf.dynobj;

  /* Make sure we know what is going on here.  */
  BFD_ASSERT (dynobj != NULL
	      && (h->needs_plt
		  || h->type == STT_GNU_IFUNC
		  || h->is_weakalias
		  || (h->def_dynamic
		      && h->ref_regular
		      && !h->def_regular)));

  /* If this is a function, put it in the procedure linkage table.  We
     will fill in the contents of the procedure linkage table later
     (although we could actually do it here).  */
  if (h->type == STT_FUNC || h->type == STT_GNU_IFUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
	  || SYMBOL_CALLS_LOCAL (info, h)
	  || (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      && h->root.type == bfd_link_hash_undefweak))
	{
	  /* This case can occur if we saw a R_RISCV_CALL_PLT reloc in an
	     input file, but the symbol was never referred to by a dynamic
	     object, or if all references were garbage collected.  In such
	     a case, we don't actually need to build a PLT entry.  */
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}

      return TRUE;
    }
  else
    h->plt.offset = (bfd_vma) -1;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (bfd_link_pic (info))
    return TRUE;

  /* If there are no references to this symbol that do not use the
     GOT, we don't need to generate a copy reloc.  */
  if (!h->non_got_ref)
    return TRUE;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* If we don't find any dynamic relocs in read-only sections, then
     we'll be keeping the dynamic relocs and avoiding the copy reloc.  */
  if (!readonly_dynrelocs (h))
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  /* We must generate a R_RISCV_COPY reloc to tell the dynamic linker
     to copy the initial value out of the dynamic object and into the
     runtime process image.  We need to remember the offset into the
     .rel.bss section we are going to use.  */
  eh = (struct riscv_elf_link_hash_entry *) h;
  if (eh->tls_type & ~GOT_NORMAL)
    {
      s = htab->sdyntdata;
      srel = htab->elf.srelbss;
    }
  else if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = htab->elf.sdynrelro;
      srel = htab->elf.sreldynrelro;
    }
  else
    {
      s = htab->elf.sdynbss;
      srel = htab->elf.srelbss;
    }
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      srel->size += sizeof (ElfNN_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct riscv_elf_link_hash_table *htab;
  struct riscv_elf_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  info = (struct bfd_link_info *) inf;
  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (htab->elf.dynamic_sections_created
      && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
	  && !h->forced_local)
	{
	  if (! bfd_elf_link_record_dynamic_symbol (info, h))
	    return FALSE;
	}

      if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, bfd_link_pic (info), h))
	{
	  asection *s = htab->elf.splt;

	  if (s->size == 0)
	    s->size = PLT_HEADER_SIZE;

	  h->plt.offset = s->size;

	  /* Make room for this entry.  */
	  s->size += PLT_ENTRY_SIZE;

	  /* We also need to make an entry in the .got.plt section.  */
	  htab->elf.sgotplt->size += GOT_ENTRY_SIZE;

	  /* We also need to make an entry in the .rela.plt section.  */
	  htab->elf.srelplt->size += sizeof (ElfNN_External_Rela);

	  /* If this symbol is not defined in a regular file, and we are
	     not generating a shared library, then set the symbol to this
	     location in the .plt.  This is required to make function
	     pointers compare as equal between the normal executable and
	     the shared library.  */
	  if (! bfd_link_pic (info)
	      && !h->def_regular)
	    {
	      h->root.u.def.section = s;
	      h->root.u.def.value = h->plt.offset;
	    }
	}
      else
	{
	  h->plt.offset = (bfd_vma) -1;
	  h->needs_plt = 0;
	}
    }
  else
    {
      h->plt.offset = (bfd_vma) -1;
      h->needs_plt = 0;
    }

  if (h->got.refcount > 0)
    {
      asection *s;
      bfd_boolean dyn;
      int tls_type = riscv_elf_hash_entry (h)->tls_type;

      /* Make sure this symbol is output as a dynamic symbol.
	 Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
	  && !h->forced_local)
	{
	  if (! bfd_elf_link_record_dynamic_symbol (info, h))
	    return FALSE;
	}

      s = htab->elf.sgot;
      h->got.offset = s->size;
      dyn = htab->elf.dynamic_sections_created;
      if (tls_type & (GOT_TLS_GD | GOT_TLS_IE))
	{
	  /* TLS_GD needs two dynamic relocs and two GOT slots.  */
	  if (tls_type & GOT_TLS_GD)
	    {
	      s->size += 2 * RISCV_ELF_WORD_BYTES;
	      htab->elf.srelgot->size += 2 * sizeof (ElfNN_External_Rela);
	    }

	  /* TLS_IE needs one dynamic reloc and one GOT slot.  */
	  if (tls_type & GOT_TLS_IE)
	    {
	      s->size += RISCV_ELF_WORD_BYTES;
	      htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	    }
	}
      else
	{
	  s->size += RISCV_ELF_WORD_BYTES;
	  if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, bfd_link_pic (info), h)
	      && ! UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    htab->elf.srelgot->size += sizeof (ElfNN_External_Rela);
	}
    }
  else
    h->got.offset = (bfd_vma) -1;

  eh = (struct riscv_elf_link_hash_entry *) h;
  if (eh->dyn_relocs == NULL)
    return TRUE;

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (bfd_link_pic (info))
    {
      if (SYMBOL_CALLS_LOCAL (info, h))
	{
	  struct elf_dyn_relocs **pp;

	  for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
	    {
	      p->count -= p->pc_count;
	      p->pc_count = 0;
	      if (p->count == 0)
		*pp = p->next;
	      else
		pp = &p->next;
	    }
	}

      /* Also discard relocs on undefined weak syms with non-default
	 visibility.  */
      if (eh->dyn_relocs != NULL
	  && h->root.type == bfd_link_hash_undefweak)
	{
	  if (ELF_ST_VISIBILITY (h->other) != STV_DEFAULT
	      || UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
	    eh->dyn_relocs = NULL;

	  /* Make sure undefined weak symbols are output as a dynamic
	     symbol in PIEs.  */
	  else if (h->dynindx == -1
		   && !h->forced_local)
	    {
	      if (! bfd_elf_link_record_dynamic_symbol (info, h))
		return FALSE;
	    }
	}
    }
  else
    {
      /* For the non-shared case, discard space for relocs against
	 symbols which turn out to need copy relocs or are not
	 dynamic.  */

      if (!h->non_got_ref
	  && ((h->def_dynamic
	       && !h->def_regular)
	      || (htab->elf.dynamic_sections_created
		  && (h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined))))
	{
	  /* Make sure this symbol is output as a dynamic symbol.
	     Undefined weak syms won't yet be marked as dynamic.  */
	  if (h->dynindx == -1
	      && !h->forced_local)
	    {
	      if (! bfd_elf_link_record_dynamic_symbol (info, h))
		return FALSE;
	    }

	  /* If that succeeded, we know we'll be keeping all the
	     relocs.  */
	  if (h->dynindx != -1)
	    goto keep;
	}

      eh->dyn_relocs = NULL;

    keep: ;
    }

  /* Finally, allocate space.  */
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc = elf_section_data (p->sec)->sreloc;
      sreloc->size += p->count * sizeof (ElfNN_External_Rela);
    }

  return TRUE;
}

/* Set DF_TEXTREL if we find any dynamic relocs that apply to
   read-only sections.  */

static bfd_boolean
maybe_set_textrel (struct elf_link_hash_entry *h, void *info_p)
{
  asection *sec;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  sec = readonly_dynrelocs (h);
  if (sec != NULL)
    {
      struct bfd_link_info *info = (struct bfd_link_info *) info_p;

      info->flags |= DF_TEXTREL;
      info->callbacks->minfo
	(_("%pB: dynamic relocation against `%pT' in read-only section `%pA'\n"),
	 sec->owner, h->root.root.string, sec);

      /* Not an error, just cut short the traversal.  */
      return FALSE;
    }
  return TRUE;
}

//FIXME: Place this somewhere sane
static unsigned ovl_max_group = 0;
static bfd_boolean
riscv_elf_overlay_preprocess(bfd *output_bfd ATTRIBUTE_UNUSED, struct bfd_link_info *info)
{
  if (riscv_comrv_debug)
    fprintf(stderr, " * riscv_elf_overlay_preprocess\n");
  struct riscv_elf_link_hash_table *htab;
  bfd *ibfd;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  if (htab->elf.dynobj == NULL)
    return TRUE;

  /* Allocate space for the overlay PLT table based on it's size
     (determined when checking the relocs).  */
  if (htab->sovlplt)
    htab->sovlplt->contents =
	(unsigned char *)bfd_zalloc (output_bfd, htab->sovlplt->size);

  /* If a grouping file has been provided it, populate the tables with valid
     entries. */
  if (!htab->ovl_tables_populated && riscv_grouping_file != NULL)
    {
      bfd_boolean ret;
      ret = parse_grouping_file (riscv_grouping_file, &htab->ovl_func_table,
				 &htab->ovl_group_list, info);
      if (!ret)
	{
	  _bfd_error_handler (_("Failed to create overlay grouping table"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      htab->ovl_tables_populated = TRUE;
      fclose (riscv_grouping_file);
    }

  /* If a grouping has not yet been specified, then try calling the
     grouping tool.  */
  if (!htab->ovl_tables_populated && riscv_use_grouping_tool)
    {
      /* Check that the --grouping-tool option was provided.  */
      if (!riscv_grouping_tool)
	{
          _bfd_error_handler (_("`--grouping-tool' option not provided, so "
	                        "the grouping tool cannot be called."));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      /* Setup the arguments for the grouping tool.  */
      /* Arguments in riscv_grouping_tool_args are semicolon separated, so there
         will be one more argument than the number of commas.  */
      int n_extra_args = 0;
      if (riscv_grouping_tool_args)
        {
          n_extra_args = 1;
          for (int i = 0; i < (int)strlen (riscv_grouping_tool_args); i++)
	    if (riscv_grouping_tool_args[i] == ';')
	      n_extra_args++;
        }

      /* Build argv for the grouping tool. */
      int n_fixed_args = 2;
      char **grouping_tool_argv =
	  malloc ((n_fixed_args + n_extra_args) * sizeof (*grouping_tool_argv));

      /* Command word */
      grouping_tool_argv[0] = riscv_grouping_tool;

      /* Copy the extra arguments from riscv_group_tools_args, each argument
         is separated by a ';' */
      const char *arg_start = riscv_grouping_tool_args;
      for (int i = 0; i < n_extra_args; i++)
	{
	  const char *arg_end = strchr (arg_start, ';');
	  int arg_len;
	  if (arg_end == NULL)
	    arg_len = strlen (arg_start);
	  else
	    arg_len = arg_end - arg_start;

	  char *tmp_arg = malloc (arg_len + 1);
	  strncpy (tmp_arg, arg_start, arg_len);
          tmp_arg[arg_len] = '\0';

	  grouping_tool_argv[i + 1] = tmp_arg;
	  arg_start = arg_end + 1;
	}

      /* Null terminate the argv list.  */
      int argc = 1 + n_extra_args;
      grouping_tool_argv[argc] = NULL;
      BFD_ASSERT (argc < (n_fixed_args + n_extra_args));

      /* Search for the input and output filenames in the list of arguments
         provided. These arguments will also be forwarded as-is to the
	 grouping tool.  */
      int in_file_arg_index = 0;
      int out_file_arg_index = 0;
      for (int i = 0; i < argc; i++)
	{
	  if (!strcmp(grouping_tool_argv[i], "--in-file"))
	    in_file_arg_index = i + 1;
	  else if (!strcmp(grouping_tool_argv[i], "--out-file"))
	    out_file_arg_index = i + 1;
	}
      /* Check that both --in-file and --out-file options were provided, and
         they were followed by file names.  */
      if (in_file_arg_index == argc)
	{
          _bfd_error_handler (_("Missing file name for `--in-file' option to "
	                        "`--grouping-tool-args'"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      if (out_file_arg_index == argc)
	{
          _bfd_error_handler (_("Missing file name for `--out-file' option to "
	                        "`--grouping-tool-args'"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      if (in_file_arg_index == 0)
	{
          _bfd_error_handler (_("No option `--in-file' provided to "
	                        "`--grouping-tool-args'"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      if (out_file_arg_index == 0)
	{
          _bfd_error_handler (_("No option `--out-file' provided to "
	                        "`--grouping-tool-args'"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      char *grouping_tool_in_filename = grouping_tool_argv[in_file_arg_index];
      char *grouping_tool_out_filename = grouping_tool_argv[out_file_arg_index];

      FILE * grouping_tool_file = fopen (grouping_tool_in_filename, FOPEN_WT);
      if (!grouping_tool_file)
	{
	  _bfd_error_handler (_("Could not open file `%s' to write input "
	                        "for grouping tool."),
			      grouping_tool_in_filename);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      BFD_ASSERT(grouping_tool_file != NULL);

      /* Emit all of the symbols which need to be grouped, plus their
         sizes to the input .csv file for the grouping tool.  */
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	{
	  unsigned int i, symcount;
	  Elf_Internal_Shdr *symtab_hdr;
	  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);

	  if (! is_riscv_elf (ibfd))
	    continue;

	  symtab_hdr = &elf_symtab_hdr (ibfd);
	  symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	              - symtab_hdr->sh_info);

	  for (i = 0; i < symcount; i++)
	    {
	      struct riscv_elf_link_hash_entry *eh =
	          (struct riscv_elf_link_hash_entry *)sym_hashes[i];
	      asection *sec = eh->elf.root.u.def.section;

	      if (!eh->needs_overlay_group)
		continue;

	      /* A symbol which needs an overlay group will be in a section with
	         a name of the format .ovlinput.<symbol name>.  */
	      if (strncmp (sec->name, ".ovlinput.",
	                   strlen(".ovlinput.")) != 0)
		continue; /* FIXME: This should be an error  */
	      const char *sym_name = sec->name + strlen(".ovlinput.");

	      fprintf (grouping_tool_file, "%s,%lu\n", sym_name, sec->size);
	    }
	}
      fclose (grouping_tool_file);

      /* call the grouping tool with the appropriate arguments.  */
      /* NOTE: The documentation for pex_one says that the flags are restricted 
         to only PEX_SEARCH, PEX_STDERR_TO_STDOUT and PEX_BINARY_OUTPUT, and
         that the output filename (outname) is interpreted as if PEX_LAST
         were set. However if this were the case then an output filename of
         NULL (as below) should cause the output to go to stdout, which it
         doesn't. In order to get the output to actually go to stdout we must
         also specify PEX_LAST in the flag field.  */
      int status, err;
      const char *errmsg = pex_one (PEX_LAST | PEX_SEARCH,
                                    grouping_tool_argv[0],
                                    grouping_tool_argv,
                                    "grouping tool", NULL, NULL,
                                    &status, &err);

      if (errmsg == NULL)
	{
	  /* Populate the tables based on the output from the grouping tool.  */
	  bfd_boolean ret;
	  FILE * grouping_tool_out_file =
	      fopen (grouping_tool_out_filename, FOPEN_RT);
	  if (!grouping_tool_out_file)
	    {
	      _bfd_error_handler (_("Could not open file `%s' to read output "
	                            "from grouping tool."),
	                          grouping_tool_out_filename);
	      bfd_set_error (bfd_error_bad_value);
	      return FALSE;
	    }
	  ret = parse_grouping_file (grouping_tool_out_file,
	                             &htab->ovl_func_table,
	                             &htab->ovl_group_list, info);
	  if (!ret)
	    {
	      _bfd_error_handler (_("Failed to create overlay grouping "
	                            "table from groupings returned from "
	                            "grouping tool."));
	      bfd_set_error (bfd_error_bad_value);
	      return FALSE;
	    }
	  htab->ovl_tables_populated = TRUE;
	}
      else
	{
	  _bfd_error_handler (_("Failed to call grouping tool: %s"),
	                      grouping_tool_argv[0]);
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
    }

  /* If there are any symbols which weren't grouped by the grouping file
     or grouping tool, then those symbols need to be put into a group on
     their own.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      if (! is_riscv_elf (ibfd))
	continue;

      unsigned next_empty_group;
      if (riscv_ovl_first_group_number != 0)
	next_empty_group = riscv_ovl_first_group_number;
      else
	next_empty_group = OVL_FIRST_FREE_GROUP;

    for (asection *sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  if (strncmp (sec->name, ".ovlinput.", strlen(".ovlinput.")) != 0)
	    continue;

	  const char *sym_name = sec->name + strlen(".ovlinput.");

	  /* Skip the symbol if it's already been assigned a group - either
	     because it was assigned by the grouping file or grouping tool,
	     or because it has just been auto assigned.  */
	  struct ovl_func_hash_entry *sym_groups =
	      ovl_func_hash_lookup (&htab->ovl_func_table,
	                            sym_name, FALSE, FALSE);
	  if (sym_groups != NULL)
	    continue;

	  /* Skip the symbol if it has been garbage collected.  */
	  if (comrv_use_gcmark && !sec->gc_mark)
	    continue;

	  /* Find the next group which is empty, starting from the
	     current value in `next_empty_group'.  */
	  char next_empty_group_str[24];
	  for ( ; ; next_empty_group++)
	    {
	      /* Also look it up in the group list.  */
	      struct ovl_group_list_entry *group_list_entry =
	          ovl_group_list_lookup (&htab->ovl_group_list,
	                                 next_empty_group, FALSE);
	      if (group_list_entry == NULL)
		break;
	    }

	  if (!ovl_update_func (&htab->ovl_func_table, sym_name,
	                        next_empty_group))
	    {
	      _bfd_error_handler (_("Failed to add %s to ovl_func_table"),
	                          sym_name);
	      bfd_set_error (bfd_error_bad_value);
	      return FALSE;
	    }

	  if (!ovl_update_group (&htab->ovl_group_list, next_empty_group,
	                         sym_name))
	    {
	      _bfd_error_handler (_("Failed to add %s to ovl_group_list"),         
	                          next_empty_group_str);
	      bfd_set_error (bfd_error_bad_value);
	      return FALSE;
	    }

	  /* The search for the next empty group will start from the group
	     number after this one.  */
	  next_empty_group += 1;
	}
      htab->ovl_tables_populated = TRUE;
    }

  /* Make sure that group 0 is allocated, since the group table and multi
     group tables will be put into this section.  */
  struct ovl_group_list_entry *group0_list_entry =
      ovl_group_list_lookup (&htab->ovl_group_list, 0, TRUE);

  BFD_ASSERT (htab->ovl_tables_populated == TRUE);
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      unsigned int i, symcount;
      Elf_Internal_Shdr *symtab_hdr;
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);

      if (! is_riscv_elf (ibfd))
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	          - symtab_hdr->sh_info);

      /* Iterate through the input symbols and if they are allocated to an
         overlay group allocate them to the next offset in that group.  */
      for (i = 0; i < symcount; i++)
	{
	  struct riscv_elf_link_hash_entry *eh =
	      (struct riscv_elf_link_hash_entry *)sym_hashes[i];
	  asection *sec = eh->elf.root.u.def.section;

	  /* Skip this symbols if it's not a definition.  */
	  if (eh->elf.root.type != bfd_link_hash_defined
	      && eh->elf.root.type != bfd_link_hash_defweak)
	    continue;

	  /* Also skip the symbol if it's already been handled here.  */
	  if (eh->overlay_groups_resolved == TRUE)
	    continue;
	  else
	    eh->overlay_groups_resolved = TRUE;

	  /* A symbol in an overlay group will be in a section with a
	     name of the format .ovlinput.<symbol name>.  */
	  if (strncmp (sec->name, ".ovlinput.", strlen(".ovlinput.")) != 0)
	    {
	      if (eh->needs_overlay_group)
		{
		  _bfd_error_handler (_("A symbol in section '%s` is in an "
		                        "overlay group, but the containing "
		                        "section does not have a "
		                        "'.ovlinput.` prefix."),
		                      sec->name);
		  bfd_set_error (bfd_error_bad_value);
		}
	      else
		continue;
	    }

	  const char *sym_name = sec->name + strlen(".ovlinput.");

	  /* Lookup all of the groups that this symbol exists in.  */
	  struct ovl_func_hash_entry *sym_groups =
	      ovl_func_hash_lookup (&htab->ovl_func_table, sym_name, FALSE,
	                            FALSE);
	  /* Every symbol that is referred to by an overlay relocation should
	     have been allocated to a group by this point. The group should
	     be provided by the grouping file, the grouping tool, or have been
	     autoassigned.  */
	  if (eh->needs_overlay_group && sym_groups == NULL)
	    {
	      _bfd_error_handler (_("Symbol '%s` is not assigned to an overlay "
	                            "group, but has been referenced as an "
	                            "overlay symbol through a relocation."),
	                            sym_name);
	      bfd_set_error (bfd_error_bad_value);
	    }

	  if (sym_groups == NULL)
	    continue;

	  /* The symbol has been assigned to an overlay group, but there
	     also exist non-overlay references to it!.  */
	  if (eh->non_overlay_reference)
	    {
	      _bfd_error_handler (_("Symbol '%s` is assigned to an overlay "
	                            "group, but is referenced by a non-overlay "
	                            "relocation."),
	                            sym_name);
	      bfd_set_error (bfd_error_bad_value);
	    }

	  /* If this is in multiple groups, then a multigroup entry needs
	     to be allocated.  */
	  if (sym_groups->multigroup == TRUE)
	    {
	      /* Calculate the size of the entry in the multigroup
	         table. A multigroup entry consists of a list of tokens
	         (4-bytes each) followed by a 4-byte 0 terminator.  */
	      int multigroup_entry_size;
	      struct ovl_func_group_info *func_group_info;

	      multigroup_entry_size = 0;
	      for (func_group_info = sym_groups->groups; 
		   func_group_info != NULL;
		   func_group_info = func_group_info->next)
		multigroup_entry_size += 4;
	      /* NULL terminator.  */
	      multigroup_entry_size += 4;

	      sym_groups->multigroup_offset = htab->ovl_multigroup_table_size;
	      htab->ovl_multigroup_table_size += multigroup_entry_size;
	    }

	  struct ovl_func_group_info *func_group_info;
	  for (func_group_info = sym_groups->groups; func_group_info != NULL;
	       func_group_info = func_group_info->next)
	    {
	      ovl_max_group = func_group_info->id > ovl_max_group
		? func_group_info->id : ovl_max_group;

	      struct ovl_group_list_entry *group_list_entry =
	          ovl_group_list_lookup (&htab->ovl_group_list,
	                                 func_group_info->id, FALSE);
	      BFD_ASSERT (group_list_entry != NULL);

	      /* Allocate the symbol's offset into the output section for the
	         group. This corresponds to the current size of the output
	         section.  */
	      func_group_info->unrelaxed_offset = group_list_entry->group_size;

	      /* Keep track of the first function which was allocated to this
	         group.  */
	      if (group_list_entry->group_size == 0)
		group_list_entry->first_func = sym_name;
	      group_list_entry->last_func = sym_name;

	      /* Allocate space in the output group for the contents of the
	         input section corresponding to the symbol, and re-pad to a
		 4-byte boundary to allow offsets to remain valid.  */
	      group_list_entry->group_size += sec->size;
	      if ((group_list_entry->group_size % 4) != 0)
		group_list_entry->group_size += (group_list_entry->group_size % 4);

	      if (group_list_entry->group_size + OVL_CRC_SZ
		  > OVL_MAXGROUPSIZE)
		{
		  info->callbacks->einfo
		    (_("%F%pB: error: Overlay group %d exceeds maximum group size\n"),
		      output_bfd, (int)func_group_info->id);
		  bfd_set_error (bfd_error_bad_value);
		}
	    }
	}
    }

  /* Now the size of any multigroups has been determined, so space for the
     multigroup table can be allocated.  */
  /* Set the size of .ovlgrptbl section, adding a placeholder last entry and
     space for a null terminator.  */
  htab->ovl_group_table_size = (ovl_max_group + 3) * 2;
  htab->ovl_group_table_max_group = ovl_max_group;
  if (htab->ovl_group_table_size % 4)
    htab->ovl_group_table_size += 4 - (htab->ovl_group_table_size % 4);

  /* Now that the size of the group table and multigroup table has been
     determined, we can use the sum of these as the size of group 0, which
     will hold these tables.  */
  group0_list_entry->group_size =
      htab->ovl_group_table_size + htab->ovl_multigroup_table_size;

  if (riscv_comrv_debug)
    {
      fprintf(stderr, "Pre-size Table\n===========\n");
      print_group_list (&htab->ovl_group_list);
      print_func_table (&htab->ovl_func_table);
    }

  /* Now that the size of the groups is fixed calculated the padded size
     of each group, finalize the offset of each group, and calculate the
     total size needed in ".ovlgrps".  */
  unsigned int i;
  bfd_vma next_group_offset = 0;
  for (i = 0; i <= ovl_max_group; i++)
    {
      struct ovl_group_list_entry *group_list_entry =
	  ovl_group_list_lookup (&htab->ovl_group_list,
	                         i, FALSE);
      /* Ignore any gaps in the table.  */
      if (group_list_entry == NULL)
	continue;

      /* Calculate the padded size of the group.  */
      group_list_entry->padded_group_size = group_list_entry->group_size;
      group_list_entry->padded_group_size += OVL_CRC_SZ;
      if (group_list_entry->padded_group_size % OVL_GROUPPAGESIZE)
	group_list_entry->padded_group_size =
	  ((group_list_entry->padded_group_size/OVL_GROUPPAGESIZE)+1)*OVL_GROUPPAGESIZE;
      
      /* Set the offset of the group to the next available offset.  */
      group_list_entry->ovlgrpdata_offset = next_group_offset;

      /* Add the padded group size to get the offet for the next group.
         The padding will be filled in once contents for the output
         section have been allocated.  */
      next_group_offset += group_list_entry->padded_group_size;
    }

  if (riscv_comrv_debug)
    {
      fprintf(stderr, "Final Table\n===========\n");
      print_group_list (&htab->ovl_group_list);
      print_func_table (&htab->ovl_func_table);
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_size_dynamic_sections (bfd *output_bfd, struct bfd_link_info *info)
{
  if (riscv_comrv_debug)
    fprintf(stderr, "* riscv_elf_size_dynamic_sections\n");
  struct riscv_elf_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd *ibfd;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;
  BFD_ASSERT (dynobj != NULL);

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter.  */
      if (bfd_link_executable (info) && !info->nointerp)
	{
	  s = bfd_get_linker_section (dynobj, ".interp");
	  BFD_ASSERT (s != NULL);
	  s->size = strlen (ELFNN_DYNAMIC_INTERPRETER) + 1;
	  s->contents = (unsigned char *) ELFNN_DYNAMIC_INTERPRETER;
	}
    }


  /* Set up .got offsets for local syms, and space for local dynamic
     relocs.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_tls_type;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      if (! is_riscv_elf (ibfd))
	continue;

      for (s = ibfd->sections; s != NULL; s = s->next)
	{
	  struct elf_dyn_relocs *p;

	  for (p = elf_section_data (s)->local_dynrel; p != NULL; p = p->next)
	    {
	      if (!bfd_is_abs_section (p->sec)
		  && bfd_is_abs_section (p->sec->output_section))
		{
		  /* Input section has been discarded, either because
		     it is a copy of a linkonce section or due to
		     linker script /DISCARD/, so we'll be discarding
		     the relocs too.  */
		}
	      else if (p->count != 0)
		{
		  srel = elf_section_data (p->sec)->sreloc;
		  srel->size += p->count * sizeof (ElfNN_External_Rela);
		  if ((p->sec->output_section->flags & SEC_READONLY) != 0)
		    info->flags |= DF_TEXTREL;
		}
	    }
	}

      local_got = elf_local_got_refcounts (ibfd);
      if (!local_got)
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_tls_type = _bfd_riscv_elf_local_got_tls_type (ibfd);
      s = htab->elf.sgot;
      srel = htab->elf.srelgot;
      for (; local_got < end_local_got; ++local_got, ++local_tls_type)
	{
	  if (*local_got > 0)
	    {
	      *local_got = s->size;
	      s->size += RISCV_ELF_WORD_BYTES;
	      if (*local_tls_type & GOT_TLS_GD)
		s->size += RISCV_ELF_WORD_BYTES;
	      if (bfd_link_pic (info)
		  || (*local_tls_type & (GOT_TLS_GD | GOT_TLS_IE)))
		srel->size += sizeof (ElfNN_External_Rela);
	    }
	  else
	    *local_got = (bfd_vma) -1;
	}
    }

  /* Allocate global sym .plt and .got entries, and space for global
     sym dynamic relocs.  */
  elf_link_hash_traverse (&htab->elf, allocate_dynrelocs, info);

  if (htab->elf.sgotplt)
    {
      struct elf_link_hash_entry *got;
      got = elf_link_hash_lookup (elf_hash_table (info),
				  "_GLOBAL_OFFSET_TABLE_",
				  FALSE, FALSE, FALSE);

      /* Don't allocate .got.plt section if there are no GOT nor PLT
	 entries and there is no refeence to _GLOBAL_OFFSET_TABLE_.  */
      if ((got == NULL
	   || !got->ref_regular_nonweak)
	  && (htab->elf.sgotplt->size == GOTPLT_HEADER_SIZE)
	  && (htab->elf.splt == NULL
	      || htab->elf.splt->size == 0)
	  && (htab->elf.sgot == NULL
	      || (htab->elf.sgot->size
		  == get_elf_backend_data (output_bfd)->got_header_size)))
	htab->elf.sgotplt->size = 0;
    }

  /* The check_relocs and adjust_dynamic_symbol entry points have
     determined the sizes of the various dynamic sections.  Allocate
     memory for them.  */
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
	continue;

      if (s == htab->elf.splt
	  || s == htab->elf.sgot
	  || s == htab->elf.sgotplt
	  || s == htab->elf.sdynbss
	  || s == htab->elf.sdynrelro
	  || s == htab->sdyntdata)
	{
	  /* Strip this section if we don't need it; see the
	     comment below.  */
	}
      else if (strncmp (s->name, ".rela", 5) == 0)
	{
	  if (s->size != 0)
	    {
	      /* We use the reloc_count field as a counter if we need
		 to copy relocs into the output file.  */
	      s->reloc_count = 0;
	    }
	}
      else
	{
	  /* It's not one of our sections.  */
	  continue;
	}

      if (s->size == 0)
	{
	  /* If we don't need this section, strip it from the
	     output file.  This is mostly to handle .rela.bss and
	     .rela.plt.  We must create both sections in
	     create_dynamic_sections, because they must be created
	     before the linker maps input sections to output
	     sections.  The linker does that before
	     adjust_dynamic_symbol is called, and it is that
	     function which decides whether anything needs to go
	     into these sections.  */
	  s->flags |= SEC_EXCLUDE;
	  continue;
	}

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
	continue;

      /* Allocate memory for the section contents.  Zero the memory
	 for the benefit of .rela.plt, which has 4 unused entries
	 at the beginning, and we don't want garbage.  */
      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
	return FALSE;
    }

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section.  We fill in the
	 values later, in riscv_elf_finish_dynamic_sections, but we
	 must add the entries now so that we get the correct size for
	 the .dynamic section.  The DT_DEBUG entry is filled in by the
	 dynamic linker and used by the debugger.  */
#define add_dynamic_entry(TAG, VAL) \
  _bfd_elf_add_dynamic_entry (info, TAG, VAL)

      if (bfd_link_executable (info))
	{
	  if (!add_dynamic_entry (DT_DEBUG, 0))
	    return FALSE;
	}

      if (htab->elf.srelplt->size != 0)
	{
	  if (!add_dynamic_entry (DT_PLTGOT, 0)
	      || !add_dynamic_entry (DT_PLTRELSZ, 0)
	      || !add_dynamic_entry (DT_PLTREL, DT_RELA)
	      || !add_dynamic_entry (DT_JMPREL, 0))
	    return FALSE;
	}

      if (!add_dynamic_entry (DT_RELA, 0)
	  || !add_dynamic_entry (DT_RELASZ, 0)
	  || !add_dynamic_entry (DT_RELAENT, sizeof (ElfNN_External_Rela)))
	return FALSE;

      /* If any dynamic relocs apply to a read-only section,
	 then we need a DT_TEXTREL entry.  */
      if ((info->flags & DF_TEXTREL) == 0)
	elf_link_hash_traverse (&htab->elf, maybe_set_textrel, info);

      if (info->flags & DF_TEXTREL)
	{
	  if (!add_dynamic_entry (DT_TEXTREL, 0))
	    return FALSE;
	}
    }
#undef add_dynamic_entry

  return TRUE;
}

#define TP_OFFSET 0
#define DTP_OFFSET 0x800

/* Return the relocation value for a TLS dtp-relative reloc.  */

static bfd_vma
dtpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - DTP_OFFSET;
}

/* Return the relocation value for a static TLS tp-relative relocation.  */

static bfd_vma
tpoff (struct bfd_link_info *info, bfd_vma address)
{
  /* If tls_sec is NULL, we should have signalled an error already.  */
  if (elf_hash_table (info)->tls_sec == NULL)
    return 0;
  return address - elf_hash_table (info)->tls_sec->vma - TP_OFFSET;
}

/* Build up a token for the overlay system.  */
static bfd_vma
ovltoken (bfd_vma multigroup, bfd_vma from_plt, bfd_vma func_off,
          bfd_vma group_id)
{
  BFD_ASSERT (multigroup <= 1);
  BFD_ASSERT (from_plt   <= 1);
  BFD_ASSERT (func_off   <= 1023);
  BFD_ASSERT (group_id   <= 65535);

  /* +--------+------+----------+----------+---------+---------+---------+
     |  31    |30-29 |   28     |    27    |  26-17  |   16-1  |    0    |
     +--------+------+----------+----------+---------+---------+---------+
     | Multi- | Heap | Reserved |   PLT    |Function | Overlay | Overlay |
     | group  |  ID  |          |          |Offset   |  Group  | Address |
     | Token  |      |          |          |         |   ID    |  Token  |
     +--------+------+----------+----------+---------+---------+---------+ */
  bfd_vma token = 0;
  token |= (multigroup & 0x1) << 31;  /* Multi-group token.  */
  token |= (0 & 0x3) << 29;           /* Heap ID.  */
  token |= (from_plt & 0x1) << 27;    /* From PLT.  */
  token |= (func_off & 0x3ff) << 17;  /* Function Offset.  */
  token |= (group_id & 0xffff) << 1;  /* Overlay Group ID.  */
  token |= (1 & 0x1) << 0;            /* Overlay Address Token.  */
  return token;
}

/* Return the relocation value for the token in the overlay system.  */

static bfd_vma
ovloff (struct bfd_link_info *info, bfd_vma from_plt,
        struct elf_link_hash_entry *entry)
{
  struct riscv_elf_link_hash_table *htab;
  htab = riscv_elf_hash_table (info);

  /* Return -1 if there is an error with this link.  */
  if (!entry)
    return 0xffffffff;

  /* Get the group(s) for the symbol.  */
  struct ovl_func_hash_entry *func_groups =
      ovl_func_hash_lookup(&htab->ovl_func_table, entry->root.root.string,
                           FALSE, FALSE);
  if (func_groups == NULL)
    {
      (*_bfd_error_handler)
	(_("error: %pB: No overlay groups for function `%s', cannot materialize overlay "
	   "token"), info->output_bfd, entry->root.root.string);
      return 0;
    }

  if (func_groups->multigroup == FALSE)
    {
      struct ovl_group_list_entry *group_list_entry =
          ovl_group_list_lookup (&htab->ovl_group_list,
                                 func_groups->groups->id, FALSE);

      bfd *ibfd;

      /* First find the input section for the first function in this
         group.  */
      char *group_first_input_sec_name;
      group_first_input_sec_name = malloc(40 + strlen(group_list_entry->first_func));
      sprintf (group_first_input_sec_name,
               ".ovlinput.__internal.duplicate.%lu.%s",
               func_groups->groups->id, group_list_entry->first_func);

      asection *group_first_input_sec = NULL;
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	{
	  group_first_input_sec =
	      bfd_get_section_by_name (ibfd, group_first_input_sec_name);
	  if (group_first_input_sec)
	    break;
	}
      if (!group_first_input_sec)
	{
	  sprintf (group_first_input_sec_name,
	           ".ovlinput.%s", group_list_entry->first_func);
	  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	    {
	      group_first_input_sec =
	          bfd_get_section_by_name (ibfd, group_first_input_sec_name);
	      if (group_first_input_sec)
		break;
	    }
	}

      /* Now find the input section for the target function in this
         group.  */
      char *target_sym_input_sec_name;
      target_sym_input_sec_name = malloc(12 + strlen(entry->root.root.string));
      sprintf (target_sym_input_sec_name,
               ".ovlinput.%s", entry->root.root.string);

      asection *target_sym_input_sec = NULL;
      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
	{
	  target_sym_input_sec =
	      bfd_get_section_by_name (ibfd, target_sym_input_sec_name);
	  if (target_sym_input_sec)
	    break;
	}
      BFD_ASSERT (group_first_input_sec != NULL);
      BFD_ASSERT (target_sym_input_sec != NULL);

      bfd_vma offset_into_group = target_sym_input_sec->output_offset
                                  - group_first_input_sec->output_offset;
      func_groups->groups->processed_offset = offset_into_group;

      if (riscv_comrv_debug)
	{
	  fprintf (stderr, "group_first_input_sec_name: %s\n", group_first_input_sec_name);
	  fprintf (stderr, "target_sym_input_sec_name:  %s\n", target_sym_input_sec_name);

	  fprintf (stderr, "group_first_input_sec->output_offset: %lu\n", group_first_input_sec->output_offset);
	  fprintf (stderr, "target_sym_input_sec->output_offset:  %lu\n", target_sym_input_sec->output_offset);

	  fprintf (stderr, "OFFSET INTO GROUP: %lu\n", offset_into_group);
	}
      BFD_ASSERT ((offset_into_group % 4) == 0);

      free(target_sym_input_sec_name);
      free(group_first_input_sec_name);
      return ovltoken(0, from_plt, offset_into_group / 4,
                      func_groups->groups->id);
    }
  else
    {
      asection *group_table_sec =
          bfd_get_section_by_name (htab->elf.dynobj,
                                   ".ovlinput.__internal.grouptables");

      /* The multigroup table is immediately after the group table. So add
         the group table size to the offset.  */
      bfd_byte *loc = group_table_sec->contents
                      + htab->ovl_group_table_size
                      + func_groups->multigroup_offset;

      /* Check if the entry in the multigroup table needs to be filled in.  */
      if (bfd_get_32 (htab->elf.dynobj, loc) == 0)
	{
	  /* Create the multigroup table entry, filling it with tokens
	     for the function in each of the groups it is contained within.  */
	  struct ovl_func_group_info *func_group_info;
	  for (func_group_info = func_groups->groups; func_group_info != NULL;
	       func_group_info = func_group_info->next)
	    {
	      bfd_vma token;
	      struct ovl_group_list_entry *group_list_entry =
	          ovl_group_list_lookup(&htab->ovl_group_list,
	                                func_group_info->id, FALSE);
	      bfd *ibfd;

	      /* First find the input section for the first function in this
	         group.  */
	      char *group_first_input_sec_name;
	      group_first_input_sec_name = malloc(40 + strlen(group_list_entry->first_func));
	      sprintf (group_first_input_sec_name,
	               ".ovlinput.__internal.duplicate.%lu.%s",
	               func_group_info->id, group_list_entry->first_func);

	      asection *group_first_input_sec = NULL;
	      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
		{
		  group_first_input_sec =
		      bfd_get_section_by_name (ibfd, group_first_input_sec_name);
		  if (group_first_input_sec)
		    break;
		}
	      if (!group_first_input_sec)
		{
		  sprintf (group_first_input_sec_name,
		           ".ovlinput.%s", group_list_entry->first_func);
		  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
		    {
		      group_first_input_sec =
		          bfd_get_section_by_name (ibfd, group_first_input_sec_name);
		      if (group_first_input_sec)
			break;
		    }
		}

	      /* Now find the input section for the target function in this
	         group.  */
	      char *target_sym_input_sec_name;
	      target_sym_input_sec_name = malloc(40 + strlen(entry->root.root.string));
	      sprintf (target_sym_input_sec_name,
		       ".ovlinput.__internal.duplicate.%lu.%s",
	               func_group_info->id, entry->root.root.string);

	      asection *target_sym_input_sec = NULL;
	      for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
		{
		  target_sym_input_sec =
		      bfd_get_section_by_name (ibfd, target_sym_input_sec_name);
		  if (target_sym_input_sec)
		    break;
		}
	      if (!target_sym_input_sec)
		{
		  sprintf (target_sym_input_sec_name,
		           ".ovlinput.%s", entry->root.root.string);
		  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
		    {
		      target_sym_input_sec =
		          bfd_get_section_by_name (ibfd, target_sym_input_sec_name);
		      if (target_sym_input_sec)
			break;
		    }
		}
	      BFD_ASSERT (group_first_input_sec != NULL);
	      BFD_ASSERT (target_sym_input_sec != NULL);

	      bfd_vma offset_into_group = target_sym_input_sec->output_offset
					  - group_first_input_sec->output_offset;
	      func_group_info->processed_offset = offset_into_group;

	      if (riscv_comrv_debug)
		{
		  fprintf (stderr, "group_first_input_sec_name: %s\n", group_first_input_sec_name);
		  fprintf (stderr, "target_sym_input_sec_name:  %s\n", target_sym_input_sec_name);

		  fprintf (stderr, "group_first_input_sec->output_offset: %lu\n", group_first_input_sec->output_offset);
		  fprintf (stderr, "target_sym_input_sec->output_offset:  %lu\n", target_sym_input_sec->output_offset);

		  fprintf (stderr, "OFFSET INTO GROUP: %lu\n", offset_into_group);
		}

	      BFD_ASSERT ((offset_into_group % 4) == 0);

	      free(target_sym_input_sec_name);
	      free(group_first_input_sec_name);
	      token = ovltoken(0, 0, offset_into_group / 4,
	                       func_group_info->id);

	      bfd_put_32 (htab->elf.dynobj, token, loc);
	      loc += OVLMULTIGROUP_ITEM_SIZE;
	    }
	  /* The list of tokens is NULL terminated.  */
	  bfd_put_32 (htab->elf.dynobj, 0, loc);
	}

      /* Create the token referring to the multigroup.  */
      bfd_vma multigroup_id;
      multigroup_id = func_groups->multigroup_offset / OVLMULTIGROUP_ITEM_SIZE;
      func_groups->multigroup_token = ovltoken(1, from_plt, 0, multigroup_id);
      return func_groups->multigroup_token;
    }
}

/* Return the global pointer's value, or 0 if it is not in use.  */

static bfd_vma
riscv_global_pointer_value (struct bfd_link_info *info)
{
  struct bfd_link_hash_entry *h;

  h = bfd_link_hash_lookup (info->hash, RISCV_GP_SYMBOL, FALSE, FALSE, TRUE);
  if (h == NULL || h->type != bfd_link_hash_defined)
    return 0;

  return h->u.def.value + sec_addr (h->u.def.section);
}

/* Emplace a static relocation.  */

static bfd_reloc_status_type
perform_relocation (const reloc_howto_type *howto,
		    const Elf_Internal_Rela *rel,
		    bfd_vma value,
		    asection *input_section,
		    bfd *input_bfd,
		    bfd_byte *contents)
{
  if (howto->pc_relative)
    value -= sec_addr (input_section) + rel->r_offset;
  value += rel->r_addend;

  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_HI20:
    case R_RISCV_TPREL_HI20:
    case R_RISCV_PCREL_HI20:
    case R_RISCV_GOT_HI20:
    case R_RISCV_TLS_GOT_HI20:
    case R_RISCV_TLS_GD_HI20:
    case R_RISCV_OVL_HI20:
    case R_RISCV_OVLPLT_HI20:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));
      break;

    case R_RISCV_LO12_I:
    case R_RISCV_GPREL_I:
    case R_RISCV_TPREL_LO12_I:
    case R_RISCV_TPREL_I:
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_OVL_LO12_I:
    case R_RISCV_OVLPLT_LO12_I:
      value = ENCODE_ITYPE_IMM (value);
      break;

    case R_RISCV_LO12_S:
    case R_RISCV_GPREL_S:
    case R_RISCV_TPREL_LO12_S:
    case R_RISCV_TPREL_S:
    case R_RISCV_PCREL_LO12_S:
      value = ENCODE_STYPE_IMM (value);
      break;

    case R_RISCV_CALL:
    case R_RISCV_CALL_PLT:
      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value))
	      | (ENCODE_ITYPE_IMM (value) << 32);
      break;

    case R_RISCV_JAL:
      if (!VALID_UJTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_UJTYPE_IMM (value);
      break;

    case R_RISCV_BRANCH:
      if (!VALID_SBTYPE_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_SBTYPE_IMM (value);
      break;

    case R_RISCV_RVC_BRANCH:
      if (!VALID_RVC_B_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_RVC_B_IMM (value);
      break;

    case R_RISCV_RVC_JUMP:
      if (!VALID_RVC_J_IMM (value))
	return bfd_reloc_overflow;
      value = ENCODE_RVC_J_IMM (value);
      break;

    case R_RISCV_RVC_LUI:
      if (RISCV_CONST_HIGH_PART (value) == 0)
	{
	  /* Linker relaxation can convert an address equal to or greater than
	     0x800 to slightly below 0x800.  C.LUI does not accept zero as a
	     valid immediate.  We can fix this by converting it to a C.LI.  */
	  bfd_vma insn = bfd_get (howto->bitsize, input_bfd,
				  contents + rel->r_offset);
	  insn = (insn & ~MATCH_C_LUI) | MATCH_C_LI;
	  bfd_put (howto->bitsize, input_bfd, insn, contents + rel->r_offset);
	  value = ENCODE_RVC_IMM (0);
	}
      else if (!VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (value)))
	return bfd_reloc_overflow;
      else
	value = ENCODE_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (value));
      break;

    case R_RISCV_32:
    case R_RISCV_64:
    case R_RISCV_ADD8:
    case R_RISCV_ADD16:
    case R_RISCV_ADD32:
    case R_RISCV_ADD64:
    case R_RISCV_SUB6:
    case R_RISCV_SUB8:
    case R_RISCV_SUB16:
    case R_RISCV_SUB32:
    case R_RISCV_SUB64:
    case R_RISCV_SET6:
    case R_RISCV_SET8:
    case R_RISCV_SET16:
    case R_RISCV_SET32:
    case R_RISCV_32_PCREL:
    case R_RISCV_TLS_DTPREL32:
    case R_RISCV_TLS_DTPREL64:
    case R_RISCV_OVL32:
    case R_RISCV_OVLPLT32:
      break;

    case R_RISCV_DELETE:
      return bfd_reloc_ok;

    default:
      return bfd_reloc_notsupported;
    }

  bfd_vma word = bfd_get (howto->bitsize, input_bfd, contents + rel->r_offset);
  word = (word & ~howto->dst_mask) | (value & howto->dst_mask);
  bfd_put (howto->bitsize, input_bfd, word, contents + rel->r_offset);

  return bfd_reloc_ok;
}

/* Remember all PC-relative high-part relocs we've encountered to help us
   later resolve the corresponding low-part relocs.  */

typedef struct
{
  bfd_vma address;
  bfd_vma value;
} riscv_pcrel_hi_reloc;

typedef struct riscv_pcrel_lo_reloc
{
  asection *			 input_section;
  struct bfd_link_info *	 info;
  reloc_howto_type *		 howto;
  const Elf_Internal_Rela *	 reloc;
  bfd_vma			 addr;
  const char *			 name;
  bfd_byte *			 contents;
  struct riscv_pcrel_lo_reloc *	 next;
} riscv_pcrel_lo_reloc;

typedef struct
{
  htab_t hi_relocs;
  riscv_pcrel_lo_reloc *lo_relocs;
} riscv_pcrel_relocs;

static hashval_t
riscv_pcrel_reloc_hash (const void *entry)
{
  const riscv_pcrel_hi_reloc *e = entry;
  return (hashval_t)(e->address >> 2);
}

static bfd_boolean
riscv_pcrel_reloc_eq (const void *entry1, const void *entry2)
{
  const riscv_pcrel_hi_reloc *e1 = entry1, *e2 = entry2;
  return e1->address == e2->address;
}

static bfd_boolean
riscv_init_pcrel_relocs (riscv_pcrel_relocs *p)
{

  p->lo_relocs = NULL;
  p->hi_relocs = htab_create (1024, riscv_pcrel_reloc_hash,
			      riscv_pcrel_reloc_eq, free);
  return p->hi_relocs != NULL;
}

static void
riscv_free_pcrel_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *cur = p->lo_relocs;

  while (cur != NULL)
    {
      riscv_pcrel_lo_reloc *next = cur->next;
      free (cur);
      cur = next;
    }

  htab_delete (p->hi_relocs);
}

static bfd_boolean
riscv_zero_pcrel_hi_reloc (Elf_Internal_Rela *rel,
			   struct bfd_link_info *info,
			   bfd_vma pc,
			   bfd_vma addr,
			   bfd_byte *contents,
			   const reloc_howto_type *howto,
			   bfd *input_bfd)
{
  /* We may need to reference low addreses in PC-relative modes even when the
   * PC is far away from these addresses.  For example, undefweak references
   * need to produce the address 0 when linked.  As 0 is far from the arbitrary
   * addresses that we can link PC-relative programs at, the linker can't
   * actually relocate references to those symbols.  In order to allow these
   * programs to work we simply convert the PC-relative auipc sequences to
   * 0-relative lui sequences.  */
  if (bfd_link_pic (info))
    return FALSE;

  /* If it's possible to reference the symbol using auipc we do so, as that's
   * more in the spirit of the PC-relative relocations we're processing.  */
  bfd_vma offset = addr - pc;
  if (ARCH_SIZE == 32 || VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (offset)))
    return FALSE;

  /* If it's impossible to reference this with a LUI-based offset then don't
   * bother to convert it at all so users still see the PC-relative relocation
   * in the truncation message.  */
  if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (addr)))
    return FALSE;

  rel->r_info = ELFNN_R_INFO(addr, R_RISCV_HI20);

  bfd_vma insn = bfd_get(howto->bitsize, input_bfd, contents + rel->r_offset);
  insn = (insn & ~MASK_AUIPC) | MATCH_LUI;
  bfd_put(howto->bitsize, input_bfd, insn, contents + rel->r_offset);
  return TRUE;
}

static bfd_boolean
riscv_record_pcrel_hi_reloc (riscv_pcrel_relocs *p, bfd_vma addr,
			     bfd_vma value, bfd_boolean absolute)
{
  bfd_vma offset = absolute ? value : value - addr;
  riscv_pcrel_hi_reloc entry = {addr, offset};
  riscv_pcrel_hi_reloc **slot =
    (riscv_pcrel_hi_reloc **) htab_find_slot (p->hi_relocs, &entry, INSERT);

  BFD_ASSERT (*slot == NULL);
  *slot = (riscv_pcrel_hi_reloc *) bfd_malloc (sizeof (riscv_pcrel_hi_reloc));
  if (*slot == NULL)
    return FALSE;
  **slot = entry;
  return TRUE;
}

static bfd_boolean
riscv_record_pcrel_lo_reloc (riscv_pcrel_relocs *p,
			     asection *input_section,
			     struct bfd_link_info *info,
			     reloc_howto_type *howto,
			     const Elf_Internal_Rela *reloc,
			     bfd_vma addr,
			     const char *name,
			     bfd_byte *contents)
{
  riscv_pcrel_lo_reloc *entry;
  entry = (riscv_pcrel_lo_reloc *) bfd_malloc (sizeof (riscv_pcrel_lo_reloc));
  if (entry == NULL)
    return FALSE;
  *entry = (riscv_pcrel_lo_reloc) {input_section, info, howto, reloc, addr,
				   name, contents, p->lo_relocs};
  p->lo_relocs = entry;
  return TRUE;
}

static bfd_boolean
riscv_resolve_pcrel_lo_relocs (riscv_pcrel_relocs *p)
{
  riscv_pcrel_lo_reloc *r;

  for (r = p->lo_relocs; r != NULL; r = r->next)
    {
      bfd *input_bfd = r->input_section->owner;

      riscv_pcrel_hi_reloc search = {r->addr, 0};
      riscv_pcrel_hi_reloc *entry = htab_find (p->hi_relocs, &search);
      if (entry == NULL
	  /* Check for overflow into bit 11 when adding reloc addend.  */
	  || (! (entry->value & 0x800)
	      && ((entry->value + r->reloc->r_addend) & 0x800)))
	{
	  char *string = (entry == NULL
			  ? "%pcrel_lo missing matching %pcrel_hi"
			  : "%pcrel_lo overflow with an addend");
	  (*r->info->callbacks->reloc_dangerous)
	    (r->info, string, input_bfd, r->input_section, r->reloc->r_offset);
	  return TRUE;
	}

      perform_relocation (r->howto, r->reloc, entry->value, r->input_section,
			  input_bfd, r->contents);
    }

  return TRUE;
}

/* Relocate a RISC-V ELF section.

   The RELOCATE_SECTION function is called by the new ELF backend linker
   to handle the relocations for a section.

   The relocs are always passed as Rela structures.

   This function is responsible for adjusting the section contents as
   necessary, and (if generating a relocatable output file) adjusting
   the reloc addend as necessary.

   This function does not have to worry about setting the reloc
   address or the reloc symbol index.

   LOCAL_SYMS is a pointer to the swapped in local symbols.

   LOCAL_SECTIONS is an array giving the section in the input file
   corresponding to the st_shndx field of each local symbol.

   The global hash table entry for the global symbols can be found
   via elf_sym_hashes (input_bfd).

   When generating relocatable output, this function must handle
   STB_LOCAL/STT_SECTION symbols specially.  The output symbol is
   going to be the section symbol corresponding to the output
   section, which means that the addend must be adjusted
   accordingly.  */

static bfd_boolean
riscv_elf_relocate_section (bfd *output_bfd,
			    struct bfd_link_info *info,
			    bfd *input_bfd,
			    asection *input_section,
			    bfd_byte *contents,
			    Elf_Internal_Rela *relocs,
			    Elf_Internal_Sym *local_syms,
			    asection **local_sections)
{
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  riscv_pcrel_relocs pcrel_relocs;
  bfd_boolean ret = FALSE;
  asection *sreloc = elf_section_data (input_section)->sreloc;
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (input_bfd);
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (input_bfd);
  bfd_vma *local_got_offsets = elf_local_got_offsets (input_bfd);
  bfd_boolean absolute;

  if (!riscv_init_pcrel_relocs (&pcrel_relocs))
    return FALSE;

  relend = relocs + input_section->reloc_count;
  for (rel = relocs; rel < relend; rel++)
    {
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma relocation;
      bfd_reloc_status_type r = bfd_reloc_ok;
      const char *name;
      bfd_vma off, ie_off;
      bfd_boolean unresolved_reloc, is_ie = FALSE;
      bfd_vma pc = sec_addr (input_section) + rel->r_offset;
      int r_type = ELFNN_R_TYPE (rel->r_info), tls_type;
      reloc_howto_type *howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
      const char *msg = NULL;
      char *msg_buf = NULL;
      bfd_boolean resolved_to_zero;

      if (howto == NULL
	  || r_type == R_RISCV_GNU_VTINHERIT || r_type == R_RISCV_GNU_VTENTRY)
	continue;

      /* This is a final link.  */
      r_symndx = ELFNN_R_SYM (rel->r_info);
      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = FALSE;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  bfd_boolean warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	  if (warned)
	    {
	      /* To avoid generating warning messages about truncated
		 relocations, set the relocation's address to be the same as
		 the start of this section.  */
	      if (input_section->output_section != NULL)
		relocation = input_section->output_section->vma;
	      else
		relocation = 0;
	    }
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      if (h != NULL)
	name = h->root.root.string;
      else
	{
	  name = (bfd_elf_string_from_elf_section
		  (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (name == NULL || *name == '\0')
	    name = bfd_section_name (sec);
	}

      resolved_to_zero = (h != NULL
			  && UNDEFWEAK_NO_DYNAMIC_RELOC (info, h));

      switch (r_type)
	{
	case R_RISCV_NONE:
	case R_RISCV_RELAX:
	case R_RISCV_TPREL_ADD:
	case R_RISCV_COPY:
	case R_RISCV_JUMP_SLOT:
	case R_RISCV_RELATIVE:
	  /* These require nothing of us at all.  */
	  continue;

	case R_RISCV_HI20:
	case R_RISCV_BRANCH:
	case R_RISCV_RVC_BRANCH:
	case R_RISCV_RVC_LUI:
	case R_RISCV_LO12_I:
	case R_RISCV_LO12_S:
	case R_RISCV_SET6:
	case R_RISCV_SET8:
	case R_RISCV_SET16:
	case R_RISCV_SET32:
	case R_RISCV_32_PCREL:
	case R_RISCV_DELETE:
	  /* These require no special handling beyond perform_relocation.  */
	  break;

	case R_RISCV_GOT_HI20:
	  if (h != NULL)
	    {
	      bfd_boolean dyn, pic;

	      off = h->got.offset;
	      BFD_ASSERT (off != (bfd_vma) -1);
	      dyn = elf_hash_table (info)->dynamic_sections_created;
	      pic = bfd_link_pic (info);

	      if (! WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, pic, h)
		  || (pic && SYMBOL_REFERENCES_LOCAL (info, h)))
		{
		  /* This is actually a static link, or it is a
		     -Bsymbolic link and the symbol is defined
		     locally, or the symbol was forced to be local
		     because of a version file.  We must initialize
		     this entry in the global offset table.  Since the
		     offset must always be a multiple of the word size,
		     we use the least significant bit to record whether
		     we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.  This
		     is done in the finish_dynamic_symbol routine.  */
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_NN (output_bfd, relocation,
				  htab->elf.sgot->contents + off);
		      h->got.offset |= 1;
		    }
		}
	      else
		unresolved_reloc = FALSE;
	    }
	  else
	    {
	      BFD_ASSERT (local_got_offsets != NULL
			  && local_got_offsets[r_symndx] != (bfd_vma) -1);

	      off = local_got_offsets[r_symndx];

	      /* The offset must always be a multiple of the word size.
		 So, we can use the least significant bit to record
		 whether we have already processed this entry.  */
	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  if (bfd_link_pic (info))
		    {
		      asection *s;
		      Elf_Internal_Rela outrel;

		      /* We need to generate a R_RISCV_RELATIVE reloc
			 for the dynamic linker.  */
		      s = htab->elf.srelgot;
		      BFD_ASSERT (s != NULL);

		      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
		      outrel.r_info =
			ELFNN_R_INFO (0, R_RISCV_RELATIVE);
		      outrel.r_addend = relocation;
		      relocation = 0;
		      riscv_elf_append_rela (output_bfd, s, &outrel);
		    }

		  bfd_put_NN (output_bfd, relocation,
			      htab->elf.sgot->contents + off);
		  local_got_offsets[r_symndx] |= 1;
		}
	    }
	  relocation = sec_addr (htab->elf.sgot) + off;
	  absolute = riscv_zero_pcrel_hi_reloc (rel,
						info,
						pc,
						relocation,
						contents,
						howto,
						input_bfd);
	  r_type = ELFNN_R_TYPE (rel->r_info);
	  howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
	  if (howto == NULL)
	    r = bfd_reloc_notsupported;
	  else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						 relocation, absolute))
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_ADD8:
	case R_RISCV_ADD16:
	case R_RISCV_ADD32:
	case R_RISCV_ADD64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value + relocation;
	  }
	  break;

	case R_RISCV_SUB6:
	case R_RISCV_SUB8:
	case R_RISCV_SUB16:
	case R_RISCV_SUB32:
	case R_RISCV_SUB64:
	  {
	    bfd_vma old_value = bfd_get (howto->bitsize, input_bfd,
					 contents + rel->r_offset);
	    relocation = old_value - relocation;
	  }
	  break;

	case R_RISCV_CALL:
	case R_RISCV_CALL_PLT:
	  /* Handle a call to an undefined weak function.  This won't be
	     relaxed, so we have to handle it here.  */
	  if (h != NULL && h->root.type == bfd_link_hash_undefweak
	      && (!bfd_link_pic (info) || h->plt.offset == MINUS_ONE))
	    {
	      /* We can use x0 as the base register.  */
	      bfd_vma insn = bfd_get_32 (input_bfd,
					 contents + rel->r_offset + 4);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (input_bfd, insn, contents + rel->r_offset + 4);
	      /* Set the relocation value so that we get 0 after the pc
		 relative adjustment.  */
	      relocation = sec_addr (input_section) + rel->r_offset;
	    }
	  /* Fall through.  */

	case R_RISCV_JAL:
	case R_RISCV_RVC_JUMP:
	  /* This line has to match the check in _bfd_riscv_relax_section.  */
	  if (bfd_link_pic (info) && h != NULL && h->plt.offset != MINUS_ONE)
	    {
	      /* Refer to the PLT entry.  */
	      relocation = sec_addr (htab->elf.splt) + h->plt.offset;
	      unresolved_reloc = FALSE;
	    }
	  break;

	case R_RISCV_TPREL_HI20:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_LO12_I:
	case R_RISCV_TPREL_LO12_S:
	  relocation = tpoff (info, relocation);
	  break;

	case R_RISCV_TPREL_I:
	case R_RISCV_TPREL_S:
	  relocation = tpoff (info, relocation);
	  if (VALID_ITYPE_IMM (relocation + rel->r_addend))
	    {
	      /* We can use tp as the base register.  */
	      bfd_vma insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      insn |= X_TP << OP_SH_RS1;
	      bfd_put_32 (input_bfd, insn, contents + rel->r_offset);
	    }
	  else
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_GPREL_I:
	case R_RISCV_GPREL_S:
	  {
	    bfd_vma gp = riscv_global_pointer_value (info);
	    bfd_boolean x0_base = VALID_ITYPE_IMM (relocation + rel->r_addend);
	    if (x0_base || VALID_ITYPE_IMM (relocation + rel->r_addend - gp))
	      {
		/* We can use x0 or gp as the base register.  */
		bfd_vma insn = bfd_get_32 (input_bfd, contents + rel->r_offset);
		insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
		if (!x0_base)
		  {
		    rel->r_addend -= gp;
		    insn |= X_GP << OP_SH_RS1;
		  }
		bfd_put_32 (input_bfd, insn, contents + rel->r_offset);
	      }
	    else
	      r = bfd_reloc_overflow;
	    break;
	  }

	case R_RISCV_PCREL_HI20:
	  absolute = riscv_zero_pcrel_hi_reloc (rel,
						info,
						pc,
						relocation,
						contents,
						howto,
						input_bfd);
	  r_type = ELFNN_R_TYPE (rel->r_info);
	  howto = riscv_elf_rtype_to_howto (input_bfd, r_type);
	  if (howto == NULL)
	    r = bfd_reloc_notsupported;
	  else if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
						 relocation + rel->r_addend,
						 absolute))
	    r = bfd_reloc_overflow;
	  break;

	case R_RISCV_PCREL_LO12_I:
	case R_RISCV_PCREL_LO12_S:
	  /* We don't allow section symbols plus addends as the auipc address,
	     because then riscv_relax_delete_bytes would have to search through
	     all relocs to update these addends.  This is also ambiguous, as
	     we do allow offsets to be added to the target address, which are
	     not to be used to find the auipc address.  */
	  if (((sym != NULL && (ELF_ST_TYPE (sym->st_info) == STT_SECTION))
	       || (h != NULL && h->type == STT_SECTION))
	      && rel->r_addend)
	    {
	      msg = _("%pcrel_lo section symbol with an addend");
	      r = bfd_reloc_dangerous;
	      break;
	    }

	  if (riscv_record_pcrel_lo_reloc (&pcrel_relocs, input_section, info,
					   howto, rel, relocation, name,
					   contents))
	    continue;
	  r = bfd_reloc_overflow;
	  break;

	case R_RISCV_TLS_DTPREL32:
	case R_RISCV_TLS_DTPREL64:
	  relocation = dtpoff (info, relocation);
	  break;

	case R_RISCV_32:
	case R_RISCV_64:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  if ((bfd_link_pic (info)
	       && (h == NULL
		   || (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		       && !resolved_to_zero)
		   || h->root.type != bfd_link_hash_undefweak)
	       && (! howto->pc_relative
		   || !SYMBOL_CALLS_LOCAL (info, h)))
	      || (!bfd_link_pic (info)
		  && h != NULL
		  && h->dynindx != -1
		  && !h->non_got_ref
		  && ((h->def_dynamic
		       && !h->def_regular)
		      || h->root.type == bfd_link_hash_undefweak
		      || h->root.type == bfd_link_hash_undefined)))
	    {
	      Elf_Internal_Rela outrel;
	      bfd_boolean skip_static_relocation, skip_dynamic_relocation;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.  */

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      skip_static_relocation = outrel.r_offset != (bfd_vma) -2;
	      skip_dynamic_relocation = outrel.r_offset >= (bfd_vma) -2;
	      outrel.r_offset += sec_addr (input_section);

	      if (skip_dynamic_relocation)
		memset (&outrel, 0, sizeof outrel);
	      else if (h != NULL && h->dynindx != -1
		       && !(bfd_link_pic (info)
			    && SYMBOLIC_BIND (info, h)
			    && h->def_regular))
		{
		  outrel.r_info = ELFNN_R_INFO (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  outrel.r_info = ELFNN_R_INFO (0, R_RISCV_RELATIVE);
		  outrel.r_addend = relocation + rel->r_addend;
		}

	      riscv_elf_append_rela (output_bfd, sreloc, &outrel);
	      if (skip_static_relocation)
		continue;
	    }
	  break;

	case R_RISCV_TLS_GOT_HI20:
	  is_ie = TRUE;
	  /* Fall through.  */

	case R_RISCV_TLS_GD_HI20:
	  if (h != NULL)
	    {
	      off = h->got.offset;
	      h->got.offset |= 1;
	    }
	  else
	    {
	      off = local_got_offsets[r_symndx];
	      local_got_offsets[r_symndx] |= 1;
	    }

	  tls_type = _bfd_riscv_elf_tls_type (input_bfd, h, r_symndx);
	  BFD_ASSERT (tls_type & (GOT_TLS_IE | GOT_TLS_GD));
	  /* If this symbol is referenced by both GD and IE TLS, the IE
	     reference's GOT slot follows the GD reference's slots.  */
	  ie_off = 0;
	  if ((tls_type & GOT_TLS_GD) && (tls_type & GOT_TLS_IE))
	    ie_off = 2 * GOT_ENTRY_SIZE;

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      int indx = 0;
	      bfd_boolean need_relocs = FALSE;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      if (h != NULL)
		{
		  bfd_boolean dyn, pic;
		  dyn = htab->elf.dynamic_sections_created;
		  pic = bfd_link_pic (info);

		  if (WILL_CALL_FINISH_DYNAMIC_SYMBOL (dyn, pic, h)
		      && (!pic || !SYMBOL_REFERENCES_LOCAL (info, h)))
		    indx = h->dynindx;
		}

	      /* The GOT entries have not been initialized yet.  Do it
		 now, and emit any relocations.  */
	      if ((bfd_link_pic (info) || indx != 0)
		  && (h == NULL
		      || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		      || h->root.type != bfd_link_hash_undefweak))
		    need_relocs = TRUE;

	      if (tls_type & GOT_TLS_GD)
		{
		  if (need_relocs)
		    {
		      outrel.r_offset = sec_addr (htab->elf.sgot) + off;
		      outrel.r_addend = 0;
		      outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_DTPMODNN);
		      bfd_put_NN (output_bfd, 0,
				  htab->elf.sgot->contents + off);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		      if (indx == 0)
			{
			  BFD_ASSERT (! unresolved_reloc);
			  bfd_put_NN (output_bfd,
				      dtpoff (info, relocation),
				      (htab->elf.sgot->contents + off +
				       RISCV_ELF_WORD_BYTES));
			}
		      else
			{
			  bfd_put_NN (output_bfd, 0,
				      (htab->elf.sgot->contents + off +
				       RISCV_ELF_WORD_BYTES));
			  outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_DTPRELNN);
			  outrel.r_offset += RISCV_ELF_WORD_BYTES;
			  riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
			}
		    }
		  else
		    {
		      /* If we are not emitting relocations for a
			 general dynamic reference, then we must be in a
			 static link or an executable link with the
			 symbol binding locally.  Mark it as belonging
			 to module 1, the executable.  */
		      bfd_put_NN (output_bfd, 1,
				  htab->elf.sgot->contents + off);
		      bfd_put_NN (output_bfd,
				  dtpoff (info, relocation),
				  (htab->elf.sgot->contents + off +
				   RISCV_ELF_WORD_BYTES));
		   }
		}

	      if (tls_type & GOT_TLS_IE)
		{
		  if (need_relocs)
		    {
		      bfd_put_NN (output_bfd, 0,
				  htab->elf.sgot->contents + off + ie_off);
		      outrel.r_offset = sec_addr (htab->elf.sgot)
				       + off + ie_off;
		      outrel.r_addend = 0;
		      if (indx == 0)
			outrel.r_addend = tpoff (info, relocation);
		      outrel.r_info = ELFNN_R_INFO (indx, R_RISCV_TLS_TPRELNN);
		      riscv_elf_append_rela (output_bfd, htab->elf.srelgot, &outrel);
		    }
		  else
		    {
		      bfd_put_NN (output_bfd, tpoff (info, relocation),
				  htab->elf.sgot->contents + off + ie_off);
		    }
		}
	    }

	  BFD_ASSERT (off < (bfd_vma) -2);
	  relocation = sec_addr (htab->elf.sgot) + off + (is_ie ? ie_off : 0);
	  if (!riscv_record_pcrel_hi_reloc (&pcrel_relocs, pc,
					    relocation, FALSE))
	    r = bfd_reloc_overflow;
	  unresolved_reloc = FALSE;
	  break;

	case R_RISCV_OVL_HI20:
	case R_RISCV_OVL_LO12_I:
	case R_RISCV_OVL32:
	  /* FIXME: Ensure we only have a raw symbol values.  */
	  relocation = ovloff (info, /*from_plt*/0, h);
	  unresolved_reloc = FALSE;
	  break;

	case R_RISCV_OVLPLT_HI20:
	case R_RISCV_OVLPLT_LO12_I:
	case R_RISCV_OVLPLT32:
	  /* FIXME: Ensure we only have a raw symbol values.  */
	  relocation = ovloff (info, /*from_plt*/1, h);

	  BFD_ASSERT (htab->sovlplt != NULL);
	  /* For now, each entry in the PLT is either empty, or the first
	      32-bits contains a previously encountered token value. First
	      try to find the index of an existing token in the PLT, if it
	      can't be found, append the token in the next unallocated entry
	      at the end.  */
	  bfd_vma offset;
	  bfd_vma next_ovlplt_offset = htab->next_ovlplt_offset;

	  for (offset = 0; offset < next_ovlplt_offset;
	       offset += OVLPLT_ENTRY_SIZE)
	    {
		bfd_vma entry = bfd_get_32 (output_bfd,
		                            htab->sovlplt->contents + offset);
		if (entry == relocation)
		  break;
	    }

	  if (offset >= next_ovlplt_offset)
	    {
	      if (h == NULL)
		return TRUE;
	      /* Store the PLT offset for this function in its metadata, this is
		 used to print the linker map later on.  */
	      struct ovl_func_hash_entry *func_groups =
		ovl_func_hash_lookup(&htab->ovl_func_table, h->root.root.string,
				     FALSE, FALSE);
	      BFD_ASSERT(func_groups != NULL);
	      BFD_ASSERT(htab->sovlplt != NULL);
	      if (func_groups == NULL || htab->sovlplt == NULL)
		return TRUE;
	      func_groups->plt_entry = TRUE;
	      func_groups->plt_offset = offset;

	      bfd_put_32 (output_bfd, relocation,
	                  htab->sovlplt->contents + offset);
	      htab->next_ovlplt_offset += OVLPLT_ENTRY_SIZE;
	    }

	  relocation = sec_addr (htab->sovlplt) + offset;

	  if (!h->def_regular)
	    {
	      /* Mark the symbol as undefined, rather than as defined in
		 the .plt section.  Leave the value alone.  */
	      sym->st_shndx = SHN_UNDEF;
	      /* If the symbol is weak, we do need to clear the value.
		 Otherwise, the PLT entry would provide a definition for
		 the symbol even if the symbol wasn't defined anywhere,
		 and so the symbol would never be NULL.  */
	      if (!h->ref_regular_nonweak)
	        sym->st_value = 0;
	    }
	  unresolved_reloc = FALSE;
	  break;

	default:
	  r = bfd_reloc_notsupported;
	}

      /* Dynamic relocs are not propagated for SEC_DEBUGGING sections
	 because such sections are not SEC_ALLOC and thus ld.so will
	 not process them.  */
      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  switch (r_type)
	    {
	    case R_RISCV_CALL:
	    case R_RISCV_JAL:
	    case R_RISCV_RVC_JUMP:
	      if (asprintf (&msg_buf,
			    _("%%X%%P: relocation %s against `%s' can "
			      "not be used when making a shared object; "
			      "recompile with -fPIC\n"),
			    howto->name,
			    h->root.root.string) == -1)
		msg_buf = NULL;
	      break;

	    default:
	      if (asprintf (&msg_buf,
			    _("%%X%%P: unresolvable %s relocation against "
			      "symbol `%s'\n"),
			    howto->name,
			    h->root.root.string) == -1)
		msg_buf = NULL;
	      break;
	    }

	  msg = msg_buf;
	  r = bfd_reloc_notsupported;
	}

      if (r == bfd_reloc_ok)
	r = perform_relocation (howto, rel, relocation, input_section,
				input_bfd, contents);

      /* We should have already detected the error and set message before.
	 If the error message isn't set since the linker runs out of memory
	 or we don't set it before, then we should set the default message
	 with the "internal error" string here.  */
      switch (r)
	{
	case bfd_reloc_ok:
	  continue;

	case bfd_reloc_overflow:
	  info->callbacks->reloc_overflow
	    (info, (h ? &h->root : NULL), name, howto->name,
	     (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	  break;

	case bfd_reloc_undefined:
	  info->callbacks->undefined_symbol
	    (info, name, input_bfd, input_section, rel->r_offset,
	     TRUE);
	  break;

	case bfd_reloc_outofrange:
	  if (msg == NULL)
	    msg = _("%X%P: internal error: out of range error\n");
	  break;

	case bfd_reloc_notsupported:
	  if (msg == NULL)
	    msg = _("%X%P: internal error: unsupported relocation error\n");
	  break;

	case bfd_reloc_dangerous:
	  /* The error message should already be set.  */
	  if (msg == NULL)
	    msg = _("dangerous relocation error");
	  info->callbacks->reloc_dangerous
	    (info, msg, input_bfd, input_section, rel->r_offset);
	  break;

	default:
	  msg = _("%X%P: internal error: unknown error\n");
	  break;
	}

      /* Do not report error message for the dangerous relocation again.  */
      if (msg && r != bfd_reloc_dangerous)
	info->callbacks->einfo (msg);

      /* Free the unused `msg_buf` if needed.  */
      if (msg_buf)
	free (msg_buf);

      /* We already reported the error via a callback, so don't try to report
	 it again by returning false.  That leads to spurious errors.  */
      ret = TRUE;
      goto out;
    }

  ret = riscv_resolve_pcrel_lo_relocs (&pcrel_relocs);
 out:
  riscv_free_pcrel_relocs (&pcrel_relocs);
  return ret;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bfd_boolean
riscv_elf_finish_dynamic_symbol (bfd *output_bfd,
				 struct bfd_link_info *info,
				 struct elf_link_hash_entry *h,
				 Elf_Internal_Sym *sym)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);

  if (h->plt.offset != (bfd_vma) -1)
    {
      /* We've decided to create a PLT entry for this symbol.  */
      bfd_byte *loc;
      bfd_vma i, header_address, plt_idx, got_address;
      uint32_t plt_entry[PLT_ENTRY_INSNS];
      Elf_Internal_Rela rela;

      BFD_ASSERT (h->dynindx != -1);

      /* Calculate the address of the PLT header.  */
      header_address = sec_addr (htab->elf.splt);

      /* Calculate the index of the entry.  */
      plt_idx = (h->plt.offset - PLT_HEADER_SIZE) / PLT_ENTRY_SIZE;

      /* Calculate the address of the .got.plt entry.  */
      got_address = riscv_elf_got_plt_val (plt_idx, info);

      /* Find out where the .plt entry should go.  */
      loc = htab->elf.splt->contents + h->plt.offset;

      /* Fill in the PLT entry itself.  */
      if (! riscv_make_plt_entry (output_bfd, got_address,
				  header_address + h->plt.offset,
				  plt_entry))
	return FALSE;

      for (i = 0; i < PLT_ENTRY_INSNS; i++)
	bfd_put_32 (output_bfd, plt_entry[i], loc + 4*i);

      /* Fill in the initial value of the .got.plt entry.  */
      loc = htab->elf.sgotplt->contents
	    + (got_address - sec_addr (htab->elf.sgotplt));
      bfd_put_NN (output_bfd, sec_addr (htab->elf.splt), loc);

      /* Fill in the entry in the .rela.plt section.  */
      rela.r_offset = got_address;
      rela.r_addend = 0;
      rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_JUMP_SLOT);

      loc = htab->elf.srelplt->contents + plt_idx * sizeof (ElfNN_External_Rela);
      bed->s->swap_reloca_out (output_bfd, &rela, loc);

      if (!h->def_regular)
	{
	  /* Mark the symbol as undefined, rather than as defined in
	     the .plt section.  Leave the value alone.  */
	  sym->st_shndx = SHN_UNDEF;
	  /* If the symbol is weak, we do need to clear the value.
	     Otherwise, the PLT entry would provide a definition for
	     the symbol even if the symbol wasn't defined anywhere,
	     and so the symbol would never be NULL.  */
	  if (!h->ref_regular_nonweak)
	    sym->st_value = 0;
	}
    }

  if (h->got.offset != (bfd_vma) -1
      && !(riscv_elf_hash_entry (h)->tls_type & (GOT_TLS_GD | GOT_TLS_IE))
      && !UNDEFWEAK_NO_DYNAMIC_RELOC (info, h))
    {
      asection *sgot;
      asection *srela;
      Elf_Internal_Rela rela;

      /* This symbol has an entry in the GOT.  Set it up.  */

      sgot = htab->elf.sgot;
      srela = htab->elf.srelgot;
      BFD_ASSERT (sgot != NULL && srela != NULL);

      rela.r_offset = sec_addr (sgot) + (h->got.offset &~ (bfd_vma) 1);

      /* If this is a local symbol reference, we just want to emit a RELATIVE
	 reloc.  This can happen if it is a -Bsymbolic link, or a pie link, or
	 the symbol was forced to be local because of a version file.
	 The entry in the global offset table will already have been
	 initialized in the relocate_section function.  */
      if (bfd_link_pic (info)
	  && SYMBOL_REFERENCES_LOCAL (info, h))
	{
	  BFD_ASSERT((h->got.offset & 1) != 0);
	  asection *sec = h->root.u.def.section;
	  rela.r_info = ELFNN_R_INFO (0, R_RISCV_RELATIVE);
	  rela.r_addend = (h->root.u.def.value
			   + sec->output_section->vma
			   + sec->output_offset);
	}
      else
	{
	  BFD_ASSERT((h->got.offset & 1) == 0);
	  BFD_ASSERT (h->dynindx != -1);
	  rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_NN);
	  rela.r_addend = 0;
	}

      bfd_put_NN (output_bfd, 0,
		  sgot->contents + (h->got.offset & ~(bfd_vma) 1));
      riscv_elf_append_rela (output_bfd, srela, &rela);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      /* This symbols needs a copy reloc.  Set it up.  */
      BFD_ASSERT (h->dynindx != -1);

      rela.r_offset = sec_addr (h->root.u.def.section) + h->root.u.def.value;
      rela.r_info = ELFNN_R_INFO (h->dynindx, R_RISCV_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;
      riscv_elf_append_rela (output_bfd, s, &rela);
    }

  /* Mark some specially defined symbols as absolute.  */
  if (h == htab->elf.hdynamic
      || (h == htab->elf.hgot || h == htab->elf.hplt))
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

/* Finish up the dynamic sections.  */

static bfd_boolean
riscv_finish_dyn (bfd *output_bfd, struct bfd_link_info *info,
		  bfd *dynobj, asection *sdyn)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (output_bfd);
  size_t dynsize = bed->s->sizeof_dyn;
  bfd_byte *dyncon, *dynconend;

  dynconend = sdyn->contents + sdyn->size;
  for (dyncon = sdyn->contents; dyncon < dynconend; dyncon += dynsize)
    {
      Elf_Internal_Dyn dyn;
      asection *s;

      bed->s->swap_dyn_in (dynobj, dyncon, &dyn);

      switch (dyn.d_tag)
	{
	case DT_PLTGOT:
	  s = htab->elf.sgotplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_JMPREL:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
	  break;
	case DT_PLTRELSZ:
	  s = htab->elf.srelplt;
	  dyn.d_un.d_val = s->size;
	  break;
	default:
	  continue;
	}

      bed->s->swap_dyn_out (output_bfd, &dyn, dyncon);
    }
  return TRUE;
}

static bfd_boolean
riscv_elf_finish_dynamic_sections (bfd *output_bfd,
				   struct bfd_link_info *info)
{
  bfd *dynobj;
  asection *sdyn;
  struct riscv_elf_link_hash_table *htab;
  bfd *ibfd;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  dynobj = htab->elf.dynobj;

  sdyn = bfd_get_linker_section (dynobj, ".dynamic");

  if (elf_hash_table (info)->dynamic_sections_created)
    {
      asection *splt;
      bfd_boolean ret;

      splt = htab->elf.splt;
      BFD_ASSERT (splt != NULL && sdyn != NULL);

      ret = riscv_finish_dyn (output_bfd, info, dynobj, sdyn);

      if (!ret)
	return ret;

      /* Fill in the head and tail entries in the procedure linkage table.  */
      if (splt->size > 0)
	{
	  int i;
	  uint32_t plt_header[PLT_HEADER_INSNS];
	  ret = riscv_make_plt_header (output_bfd,
				       sec_addr (htab->elf.sgotplt),
				       sec_addr (splt), plt_header);
	  if (!ret)
	    return ret;

	  for (i = 0; i < PLT_HEADER_INSNS; i++)
	    bfd_put_32 (output_bfd, plt_header[i], splt->contents + 4*i);

	  elf_section_data (splt->output_section)->this_hdr.sh_entsize
	    = PLT_ENTRY_SIZE;
	}
    }

  /* Fill in all of the overlay PLT entries in turn, based on the
     token value at the start of each entry.  */
  if (htab->overlay_enabled)
  {
    if (htab->sovlplt)
      {
	bfd_vma off, i, token;
	uint32_t ovlplt_entry[OVLPLT_ENTRY_INSNS];

	for (off = 0; off < htab->next_ovlplt_offset;
	     off += OVLPLT_ENTRY_SIZE)
	  {
	    token = bfd_get_32 (output_bfd, htab->sovlplt->contents + off);
	    if (! riscv_make_ovlplt_entry (token, ovlplt_entry))
	      return FALSE;

	    for (i = 0; i < OVLPLT_ENTRY_INSNS; i++)
	      bfd_put_32 (output_bfd, ovlplt_entry[i],
			  htab->sovlplt->contents + off + 4*i);
	  }
      }

    /* Fill in all the .ovlgrptbl table entries. */
    {
      asection *group_table_sec =
        bfd_get_section_by_name (htab->elf.dynobj, ".ovlinput.__internal.grouptables");

      bfd_vma offset = 0;
      unsigned group = 0;
      unsigned max_group = htab->ovl_group_table_max_group;
      for (group = 0; group <= (max_group + 1); group++)
	{
	  /* Store current offset.  */
	  uint16_t offset_stored = offset / 512;
	  bfd_put_16 (htab->elf.dynobj, offset_stored,
		      group_table_sec->contents + group * 2);

	  struct ovl_group_list_entry *group_list_entry =
	    ovl_group_list_lookup (&htab->ovl_group_list, group, FALSE);
	  if (group_list_entry)
	    offset += group_list_entry->padded_group_size;
	}
      /* The last entry in the .ovlgrptbl is a null terminator.  */
      bfd_put_16 (htab->elf.dynobj, 0,
		  group_table_sec->contents + ((max_group + 2) * 2));
      /* There might also be some space after .ovlgrptbl to bring the
         subsequent multigroup table into alignment. Fill that with nulls too */
      unsigned i;
      for (i = (max_group + 3) * 2; i < htab->ovl_group_table_size; i++)
	bfd_put_8 (htab->elf.dynobj, 0, group_table_sec->contents + i);
    }

    unsigned char *current_data;
    build_current_ovl_section(info, (void*)&current_data);
    BFD_ASSERT(current_data != NULL);
    for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
      {
	asection *isec;
	for (isec = ibfd->sections; isec != NULL; isec = isec->next)
	  {
	    if (strncmp(isec->name, ".ovlinput.", strlen(".ovlinput.")) == 0)
	      {
		struct ovl_func_hash_entry *sym_groups =
	          ovl_func_hash_lookup (&htab->ovl_func_table,
	                                isec->name + strlen(".ovlinput."),
	                                FALSE, FALSE);
		if (sym_groups == NULL)
		  continue;

		struct ovl_func_group_info *func_group_info;
		for (func_group_info = sym_groups->groups->next; func_group_info != NULL;
		     func_group_info = func_group_info->next)
		  {
		    char *duplicate_func_name;
		    duplicate_func_name = malloc(40 + strlen(isec->name));
		    sprintf (duplicate_func_name, ".ovlinput.__internal.duplicate.%lu.%s",
			     func_group_info->id, isec->name + strlen(".ovlinput."));

		    if (riscv_comrv_debug)
		      fprintf(stderr, "- Copy of %s in group %lu (%s)\n", isec->name,
			      func_group_info->id, duplicate_func_name);
		    asection *dup_sec = bfd_get_section_by_name(htab->elf.dynobj, duplicate_func_name);
		    free(duplicate_func_name);
		    BFD_ASSERT(dup_sec != NULL);

		    /* Nasty hack: When the .ovlgrps output section is created it
		       is created with its flags initialized to the same flags as the
		       last constituent input section. Because the last input section
		       is a dynamic section, the output section erroneously picks up the
		       SEC_IN_MEMORY flag which causes bfd_get_section_contents to
		       fail when it tries to read from the "contents" of .ovlgrps.  */
		    isec->output_section->flags &= ~ SEC_IN_MEMORY;

		    bfd_get_section_contents (output_bfd, isec->output_section,
					      dup_sec->contents, isec->output_offset,
					      dup_sec->size);
		  }
	      }
	  }
      }
    free(current_data);

    /* Now all functions have been copied, calculate and insert the overlay
       section padding and CRC.  */
    emit_ovl_padding_and_crc (&htab->ovl_group_list, info);
  }

  if (htab->elf.sgotplt)
    {
      asection *output_section = htab->elf.sgotplt->output_section;

      if (bfd_is_abs_section (output_section))
	{
	  (*_bfd_error_handler)
	    (_("discarded output section: `%pA'"), htab->elf.sgotplt);
	  return FALSE;
	}

      if (htab->elf.sgotplt->size > 0)
	{
	  /* Write the first two entries in .got.plt, needed for the dynamic
	     linker.  */
	  bfd_put_NN (output_bfd, (bfd_vma) -1, htab->elf.sgotplt->contents);
	  bfd_put_NN (output_bfd, (bfd_vma) 0,
		      htab->elf.sgotplt->contents + GOT_ENTRY_SIZE);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  if (htab->elf.sgot)
    {
      asection *output_section = htab->elf.sgot->output_section;

      if (htab->elf.sgot->size > 0)
	{
	  /* Set the first entry in the global offset table to the address of
	     the dynamic section.  */
	  bfd_vma val = sdyn ? sec_addr (sdyn) : 0;
	  bfd_put_NN (output_bfd, val, htab->elf.sgot->contents);
	}

      elf_section_data (output_section)->this_hdr.sh_entsize = GOT_ENTRY_SIZE;
    }

  return TRUE;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma) -1 if it should not be included.  */

static bfd_vma
riscv_elf_plt_sym_val (bfd_vma i, const asection *plt,
		       const arelent *rel ATTRIBUTE_UNUSED)
{
  return plt->vma + PLT_HEADER_SIZE + i * PLT_ENTRY_SIZE;
}

static enum elf_reloc_type_class
riscv_reloc_type_class (const struct bfd_link_info *info ATTRIBUTE_UNUSED,
			const asection *rel_sec ATTRIBUTE_UNUSED,
			const Elf_Internal_Rela *rela)
{
  switch (ELFNN_R_TYPE (rela->r_info))
    {
    case R_RISCV_RELATIVE:
      return reloc_class_relative;
    case R_RISCV_JUMP_SLOT:
      return reloc_class_plt;
    case R_RISCV_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Given the ELF header flags in FLAGS, it returns a string that describes the
   float ABI.  */

static const char *
riscv_float_abi_string (flagword flags)
{
  switch (flags & EF_RISCV_FLOAT_ABI)
    {
    case EF_RISCV_FLOAT_ABI_SOFT:
      return "soft-float";
      break;
    case EF_RISCV_FLOAT_ABI_SINGLE:
      return "single-float";
      break;
    case EF_RISCV_FLOAT_ABI_DOUBLE:
      return "double-float";
      break;
    case EF_RISCV_FLOAT_ABI_QUAD:
      return "quad-float";
      break;
    default:
      abort ();
    }
}

/* The information of architecture attribute.  */
static riscv_subset_list_t in_subsets;
static riscv_subset_list_t out_subsets;
static riscv_subset_list_t merged_subsets;

/* Predicator for standard extension.  */

static bfd_boolean
riscv_std_ext_p (const char *name)
{
  return (strlen (name) == 1) && (name[0] != 'x') && (name[0] != 's');
}

/* Error handler when version mis-match.  */

static void
riscv_version_mismatch (bfd *ibfd,
			struct riscv_subset_t *in,
			struct riscv_subset_t *out)
{
  _bfd_error_handler
    (_("error: %pB: Mis-matched ISA version for '%s' extension. "
       "%d.%d vs %d.%d"),
       ibfd, in->name,
       in->major_version, in->minor_version,
       out->major_version, out->minor_version);
}

/* Return true if subset is 'i' or 'e'.  */

static bfd_boolean
riscv_i_or_e_p (bfd *ibfd,
		const char *arch,
		struct riscv_subset_t *subset)
{
  if ((strcasecmp (subset->name, "e") != 0)
      && (strcasecmp (subset->name, "i") != 0))
    {
      _bfd_error_handler
	(_("error: %pB: corrupted ISA string '%s'. "
	   "First letter should be 'i' or 'e' but got '%s'."),
	   ibfd, arch, subset->name);
      return FALSE;
    }
  return TRUE;
}

/* Merge standard extensions.

   Return Value:
     Return FALSE if failed to merge.

   Arguments:
     `bfd`: bfd handler.
     `in_arch`: Raw arch string for input object.
     `out_arch`: Raw arch string for output object.
     `pin`: subset list for input object, and it'll skip all merged subset after
            merge.
     `pout`: Like `pin`, but for output object.  */

static bfd_boolean
riscv_merge_std_ext (bfd *ibfd,
		     const char *in_arch,
		     const char *out_arch,
		     struct riscv_subset_t **pin,
		     struct riscv_subset_t **pout)
{
  const char *standard_exts = riscv_supported_std_ext ();
  const char *p;
  struct riscv_subset_t *in = *pin;
  struct riscv_subset_t *out = *pout;

  /* First letter should be 'i' or 'e'.  */
  if (!riscv_i_or_e_p (ibfd, in_arch, in))
    return FALSE;

  if (!riscv_i_or_e_p (ibfd, out_arch, out))
    return FALSE;

  if (in->name[0] != out->name[0])
    {
      /* TODO: We might allow merge 'i' with 'e'.  */
      _bfd_error_handler
	(_("error: %pB: Mis-matched ISA string to merge '%s' and '%s'."),
	 ibfd, in->name, out->name);
      return FALSE;
    }
  else if ((in->major_version != out->major_version) ||
	   (in->minor_version != out->minor_version))
    {
      /* TODO: Allow different merge policy.  */
      riscv_version_mismatch (ibfd, in, out);
      return FALSE;
    }
  else
    riscv_add_subset (&merged_subsets,
		      in->name, in->major_version, in->minor_version);

  in = in->next;
  out = out->next;

  /* Handle standard extension first.  */
  for (p = standard_exts; *p; ++p)
    {
      char find_ext[2] = {*p, '\0'};
      struct riscv_subset_t *find_in =
	riscv_lookup_subset (&in_subsets, find_ext);
      struct riscv_subset_t *find_out =
	riscv_lookup_subset (&out_subsets, find_ext);

      if (find_in == NULL && find_out == NULL)
	continue;

      /* Check version is same or not.  */
      /* TODO: Allow different merge policy.  */
      if ((find_in != NULL && find_out != NULL)
	  && ((find_in->major_version != find_out->major_version)
	      || (find_in->minor_version != find_out->minor_version)))
	{
	  riscv_version_mismatch (ibfd, in, out);
	  return FALSE;
	}

      struct riscv_subset_t *merged = find_in ? find_in : find_out;
      riscv_add_subset (&merged_subsets, merged->name,
			merged->major_version, merged->minor_version);
    }

  /* Skip all standard extensions.  */
  while ((in != NULL) && riscv_std_ext_p (in->name)) in = in->next;
  while ((out != NULL) && riscv_std_ext_p (out->name)) out = out->next;

  *pin = in;
  *pout = out;

  return TRUE;
}

/* If C is a prefix class, then return the EXT string without the prefix.
   Otherwise return the entire EXT string.  */

static const char *
riscv_skip_prefix (const char *ext, riscv_isa_ext_class_t c)
{
  switch (c)
    {
    case RV_ISA_CLASS_X: return &ext[1];
    case RV_ISA_CLASS_S: return &ext[1];
    case RV_ISA_CLASS_Z: return &ext[1];
    default: return ext;
    }
}

/* Compare prefixed extension names canonically.  */

static int
riscv_prefix_cmp (const char *a, const char *b)
{
  riscv_isa_ext_class_t ca = riscv_get_prefix_class (a);
  riscv_isa_ext_class_t cb = riscv_get_prefix_class (b);

  /* Extension name without prefix  */
  const char *anp = riscv_skip_prefix (a, ca);
  const char *bnp = riscv_skip_prefix (b, cb);

  if (ca == cb)
    return strcasecmp (anp, bnp);

  return (int)ca - (int)cb;
}

/* Merge multi letter extensions.  PIN is a pointer to the head of the input
   object subset list.  Likewise for POUT and the output object.  Return TRUE
   on success and FALSE when a conflict is found.  */

static bfd_boolean
riscv_merge_multi_letter_ext (bfd *ibfd,
			      riscv_subset_t **pin,
			      riscv_subset_t **pout)
{
  riscv_subset_t *in = *pin;
  riscv_subset_t *out = *pout;
  riscv_subset_t *tail;

  int cmp;

  while (in && out)
    {
      cmp = riscv_prefix_cmp (in->name, out->name);

      if (cmp < 0)
	{
	  /* `in' comes before `out', append `in' and increment.  */
	  riscv_add_subset (&merged_subsets, in->name, in->major_version,
			    in->minor_version);
	  in = in->next;
	}
      else if (cmp > 0)
	{
	  /* `out' comes before `in', append `out' and increment.  */
	  riscv_add_subset (&merged_subsets, out->name, out->major_version,
			    out->minor_version);
	  out = out->next;
	}
      else
	{
	  /* Both present, check version and increment both.  */
	  if ((in->major_version != out->major_version)
	      || (in->minor_version != out->minor_version))
	    {
	      riscv_version_mismatch (ibfd, in, out);
	      return FALSE;
	    }

	  riscv_add_subset (&merged_subsets, out->name, out->major_version,
			    out->minor_version);
	  out = out->next;
	  in = in->next;
	}
    }

  if (in || out) {
    /* If we're here, either `in' or `out' is running longer than
       the other. So, we need to append the corresponding tail.  */
    tail = in ? in : out;

    while (tail)
      {
	riscv_add_subset (&merged_subsets, tail->name, tail->major_version,
			  tail->minor_version);
	tail = tail->next;
      }
  }

  return TRUE;
}

/* Merge Tag_RISCV_arch attribute.  */

static char *
riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
{
  riscv_subset_t *in, *out;
  char *merged_arch_str;

  unsigned xlen_in, xlen_out;
  merged_subsets.head = NULL;
  merged_subsets.tail = NULL;

  riscv_parse_subset_t rpe_in;
  riscv_parse_subset_t rpe_out;

  rpe_in.subset_list = &in_subsets;
  rpe_in.error_handler = _bfd_error_handler;
  rpe_in.xlen = &xlen_in;

  rpe_out.subset_list = &out_subsets;
  rpe_out.error_handler = _bfd_error_handler;
  rpe_out.xlen = &xlen_out;

  if (in_arch == NULL && out_arch == NULL)
    return NULL;

  if (in_arch == NULL && out_arch != NULL)
    return out_arch;

  if (in_arch != NULL && out_arch == NULL)
    return in_arch;

  /* Parse subset from arch string.  */
  if (!riscv_parse_subset (&rpe_in, in_arch))
    return NULL;

  if (!riscv_parse_subset (&rpe_out, out_arch))
    return NULL;

  /* Checking XLEN.  */
  if (xlen_out != xlen_in)
    {
      _bfd_error_handler
	(_("error: %pB: ISA string of input (%s) doesn't match "
	   "output (%s)."), ibfd, in_arch, out_arch);
      return NULL;
    }

  /* Merge subset list.  */
  in = in_subsets.head;
  out = out_subsets.head;

  /* Merge standard extension.  */
  if (!riscv_merge_std_ext (ibfd, in_arch, out_arch, &in, &out))
    return NULL;

  /* Merge all non-single letter extensions with single call.  */
  if (!riscv_merge_multi_letter_ext (ibfd, &in, &out))
    return NULL;

  if (xlen_in != xlen_out)
    {
      _bfd_error_handler
	(_("error: %pB: XLEN of input (%u) doesn't match "
	   "output (%u)."), ibfd, xlen_in, xlen_out);
      return NULL;
    }

  if (xlen_in != ARCH_SIZE)
    {
      _bfd_error_handler
	(_("error: %pB: Unsupported XLEN (%u), you might be "
	   "using wrong emulation."), ibfd, xlen_in);
      return NULL;
    }

  merged_arch_str = riscv_arch_str (ARCH_SIZE, &merged_subsets);

  /* Release the subset lists.  */
  riscv_release_subset_list (&in_subsets);
  riscv_release_subset_list (&out_subsets);
  riscv_release_subset_list (&merged_subsets);

  return merged_arch_str;
}

/* Merge object attributes from IBFD into output_bfd of INFO.
   Raise an error if there are conflicting attributes.  */

static bfd_boolean
riscv_merge_attributes (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  obj_attribute *in_attr;
  obj_attribute *out_attr;
  bfd_boolean result = TRUE;
  const char *sec_name = get_elf_backend_data (ibfd)->obj_attrs_section;
  unsigned int i;

  /* Skip linker created files.  */
  if (ibfd->flags & BFD_LINKER_CREATED)
    return TRUE;

  /* Skip any input that doesn't have an attribute section.
     This enables to link object files without attribute section with
     any others.  */
  if (bfd_get_section_by_name (ibfd, sec_name) == NULL)
    return TRUE;

  if (!elf_known_obj_attributes_proc (obfd)[0].i)
    {
      /* This is the first object.  Copy the attributes.  */
      _bfd_elf_copy_obj_attributes (ibfd, obfd);

      out_attr = elf_known_obj_attributes_proc (obfd);

      /* Use the Tag_null value to indicate the attributes have been
	 initialized.  */
      out_attr[0].i = 1;

      return TRUE;
    }

  in_attr = elf_known_obj_attributes_proc (ibfd);
  out_attr = elf_known_obj_attributes_proc (obfd);

  for (i = LEAST_KNOWN_OBJ_ATTRIBUTE; i < NUM_KNOWN_OBJ_ATTRIBUTES; i++)
    {
    switch (i)
      {
      case Tag_RISCV_arch:
	if (!out_attr[Tag_RISCV_arch].s)
	  out_attr[Tag_RISCV_arch].s = in_attr[Tag_RISCV_arch].s;
	else if (in_attr[Tag_RISCV_arch].s
		 && out_attr[Tag_RISCV_arch].s)
	  {
	    /* Check arch compatible.  */
	    char *merged_arch =
		riscv_merge_arch_attr_info (ibfd,
					    in_attr[Tag_RISCV_arch].s,
					    out_attr[Tag_RISCV_arch].s);
	    if (merged_arch == NULL)
	      {
		result = FALSE;
		out_attr[Tag_RISCV_arch].s = "";
	      }
	    else
	      out_attr[Tag_RISCV_arch].s = merged_arch;
	  }
	break;
      case Tag_RISCV_priv_spec:
      case Tag_RISCV_priv_spec_minor:
      case Tag_RISCV_priv_spec_revision:
	if (out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB: conflicting priv spec version "
		 "(major/minor/revision)."), ibfd);
	    result = FALSE;
	  }
	break;
      case Tag_RISCV_unaligned_access:
	out_attr[i].i |= in_attr[i].i;
	break;
      case Tag_RISCV_stack_align:
	if (out_attr[i].i == 0)
	  out_attr[i].i = in_attr[i].i;
	else if (in_attr[i].i != 0
		 && out_attr[i].i != 0
		 && out_attr[i].i != in_attr[i].i)
	  {
	    _bfd_error_handler
	      (_("error: %pB use %u-byte stack aligned but the output "
		 "use %u-byte stack aligned."),
	       ibfd, in_attr[i].i, out_attr[i].i);
	    result = FALSE;
	  }
	break;
      default:
	result &= _bfd_elf_merge_unknown_attribute_low (ibfd, obfd, i);
      }

      /* If out_attr was copied from in_attr then it won't have a type yet.  */
      if (in_attr[i].type && !out_attr[i].type)
	out_attr[i].type = in_attr[i].type;
    }

  /* Merge Tag_compatibility attributes and any common GNU ones.  */
  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return FALSE;

  /* Check for any attributes not known on RISC-V.  */
  result &= _bfd_elf_merge_unknown_attribute_list (ibfd, obfd);

  return result;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

static bfd_boolean
_bfd_riscv_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
{
  bfd *obfd = info->output_bfd;
  flagword new_flags, old_flags;

  if (!is_riscv_elf (ibfd) || !is_riscv_elf (obfd))
    return TRUE;

  if (strcmp (bfd_get_target (ibfd), bfd_get_target (obfd)) != 0)
    {
      (*_bfd_error_handler)
	(_("%pB: ABI is incompatible with that of the selected emulation:\n"
	   "  target emulation `%s' does not match `%s'"),
	 ibfd, bfd_get_target (ibfd), bfd_get_target (obfd));
      return FALSE;
    }

  if (!_bfd_elf_merge_object_attributes (ibfd, info))
    return FALSE;

  if (!riscv_merge_attributes (ibfd, info))
    return FALSE;

  new_flags = elf_elfheader (ibfd)->e_flags;
  old_flags = elf_elfheader (obfd)->e_flags;

  if (! elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = TRUE;
      elf_elfheader (obfd)->e_flags = new_flags;
      return TRUE;
    }

  /* Check to see if the input BFD actually contains any sections.  If not,
     its flags may not have been initialized either, but it cannot actually
     cause any incompatibility.  Do not short-circuit dynamic objects; their
     section list may be emptied by elf_link_add_object_symbols.

     Also check to see if there are no code sections in the input.  In this
     case, there is no need to check for code specific flags.  */
  if (!(ibfd->flags & DYNAMIC))
    {
      bfd_boolean null_input_bfd = TRUE;
      bfd_boolean only_data_sections = TRUE;
      asection *sec;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  if ((bfd_section_flags (sec)
	       & (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	      == (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
	    only_data_sections = FALSE;

	  null_input_bfd = FALSE;
	  break;
	}

      if (null_input_bfd || only_data_sections)
	return TRUE;
    }

  /* Disallow linking different float ABIs.  */
  if ((old_flags ^ new_flags) & EF_RISCV_FLOAT_ABI)
    {
      (*_bfd_error_handler)
	(_("%pB: can't link %s modules with %s modules"), ibfd,
	 riscv_float_abi_string (new_flags),
	 riscv_float_abi_string (old_flags));
      goto fail;
    }

  /* Disallow linking RVE and non-RVE.  */
  if ((old_flags ^ new_flags) & EF_RISCV_RVE)
    {
      (*_bfd_error_handler)
       (_("%pB: can't link RVE with other target"), ibfd);
      goto fail;
    }

  /* Allow linking RVC and non-RVC, and keep the RVC flag.  */
  elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_RVC;

  return TRUE;

 fail:
  bfd_set_error (bfd_error_bad_value);
  return FALSE;
}

/* Delete some bytes from a section while relaxing.  */

static bfd_boolean
riscv_relax_delete_bytes (bfd *abfd, asection *sec, bfd_vma addr, size_t count,
			  struct bfd_link_info *link_info)
{
  unsigned int i, symcount;
  bfd_vma toaddr = sec->size;
  struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (abfd);
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  unsigned int sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  bfd_byte *contents = data->this_hdr.contents;

  /* Actually delete the bytes.  */
  sec->size -= count;

  /* If this is in any overlay groups then the corresponding padding sections
     for those groups need to be resized, as do any duplicates.  */
  if (strncmp (sec->name, ".ovlinput.", strlen(".ovlinput.")) == 0)
    {
      struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (link_info);

      const char *sym_name = sec->name + strlen(".ovlinput.");
      struct ovl_func_hash_entry *func_entry =
          ovl_func_hash_lookup (&htab->ovl_func_table, sym_name, FALSE, FALSE);
      if (func_entry)
	{
	  struct ovl_func_group_info *groups;
	  /* Get the accompanying padding sections and increase their size.  */
	  char group_padding_section_name[40];
	  for (groups = func_entry->groups; groups != NULL;
	       groups = groups->next)
	    {
	      sprintf (group_padding_section_name,
	               ".ovlinput.__internal.padding.%lu",
	               groups->id);
	      asection *group_padding_section =
	          bfd_get_section_by_name (htab->elf.dynobj,
	                                   group_padding_section_name);
	      if (group_padding_section)
		group_padding_section->size += count;
	    }

	  /* Get any duplicated sections and reduce their size.  */
	  char *sym_duplicate_section_name;
	  sym_duplicate_section_name = malloc(40 + strlen(sym_name));
	  for (groups = func_entry->groups; groups != NULL;
	       groups = groups->next)
	    {
	      sprintf (sym_duplicate_section_name,
	               ".ovlinput.__internal.duplicate.%lu.%s",
	               groups->id, sym_name);
	      asection *sym_duplicate_section =
	          bfd_get_section_by_name (htab->elf.dynobj,
		                           sym_duplicate_section_name);
	      if (sym_duplicate_section)
		sym_duplicate_section->size -= count;
	    }
	  free(sym_duplicate_section_name);
	}
    }

  memmove (contents + addr, contents + addr + count, toaddr - addr - count);

  /* Adjust the location of all of the relocs.  Note that we need not
     adjust the addends, since all PC-relative references must be against
     symbols, which we will adjust below.  */
  for (i = 0; i < sec->reloc_count; i++)
    if (data->relocs[i].r_offset > addr && data->relocs[i].r_offset < toaddr)
      data->relocs[i].r_offset -= count;

  /* Adjust the local symbols defined in this section.  */
  for (i = 0; i < symtab_hdr->sh_info; i++)
    {
      Elf_Internal_Sym *sym = (Elf_Internal_Sym *) symtab_hdr->contents + i;
      if (sym->st_shndx == sec_shndx)
	{
	  /* If the symbol is in the range of memory we just moved, we
	     have to adjust its value.  */
	  if (sym->st_value > addr && sym->st_value <= toaddr)
	    sym->st_value -= count;

	  /* If the symbol *spans* the bytes we just deleted (i.e. its
	     *end* is in the moved bytes but its *start* isn't), then we
	     must adjust its size.

	     This test needs to use the original value of st_value, otherwise
	     we might accidentally decrease size when deleting bytes right
	     before the symbol.  But since deleted relocs can't span across
	     symbols, we can't have both a st_value and a st_size decrease,
	     so it is simpler to just use an else.  */
	  else if (sym->st_value <= addr
		   && sym->st_value + sym->st_size > addr
		   && sym->st_value + sym->st_size <= toaddr)
	    sym->st_size -= count;
	}
    }

  /* Now adjust the global symbols defined in this section.  */
  symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	      - symtab_hdr->sh_info);

  for (i = 0; i < symcount; i++)
    {
      struct elf_link_hash_entry *sym_hash = sym_hashes[i];

      /* The '--wrap SYMBOL' option is causing a pain when the object file,
	 containing the definition of __wrap_SYMBOL, includes a direct
	 call to SYMBOL as well. Since both __wrap_SYMBOL and SYMBOL reference
	 the same symbol (which is __wrap_SYMBOL), but still exist as two
	 different symbols in 'sym_hashes', we don't want to adjust
	 the global symbol __wrap_SYMBOL twice.  */
      /* The same problem occurs with symbols that are versioned_hidden, as
	 foo becomes an alias for foo@BAR, and hence they need the same
	 treatment.  */
      if (link_info->wrap_hash != NULL
	  || sym_hash->versioned == versioned_hidden)
	{
	  struct elf_link_hash_entry **cur_sym_hashes;

	  /* Loop only over the symbols which have already been checked.  */
	  for (cur_sym_hashes = sym_hashes; cur_sym_hashes < &sym_hashes[i];
	       cur_sym_hashes++)
	    {
	      /* If the current symbol is identical to 'sym_hash', that means
		 the symbol was already adjusted (or at least checked).  */
	      if (*cur_sym_hashes == sym_hash)
		break;
	    }
	  /* Don't adjust the symbol again.  */
	  if (cur_sym_hashes < &sym_hashes[i])
	    continue;
	}

      if ((sym_hash->root.type == bfd_link_hash_defined
	   || sym_hash->root.type == bfd_link_hash_defweak)
	  && sym_hash->root.u.def.section == sec)
	{
	  /* As above, adjust the value if needed.  */
	  if (sym_hash->root.u.def.value > addr
	      && sym_hash->root.u.def.value <= toaddr)
	    sym_hash->root.u.def.value -= count;

	  /* As above, adjust the size if needed.  */
	  else if (sym_hash->root.u.def.value <= addr
		   && sym_hash->root.u.def.value + sym_hash->size > addr
		   && sym_hash->root.u.def.value + sym_hash->size <= toaddr)
	    sym_hash->size -= count;
	}
    }

  return TRUE;
}

/* A second format for recording PC-relative hi relocations.  This stores the
   information required to relax them to GP-relative addresses.  */

typedef struct riscv_pcgp_hi_reloc riscv_pcgp_hi_reloc;
struct riscv_pcgp_hi_reloc
{
  bfd_vma hi_sec_off;
  bfd_vma hi_addend;
  bfd_vma hi_addr;
  unsigned hi_sym;
  asection *sym_sec;
  bfd_boolean undefined_weak;
  riscv_pcgp_hi_reloc *next;
};

typedef struct riscv_pcgp_lo_reloc riscv_pcgp_lo_reloc;
struct riscv_pcgp_lo_reloc
{
  bfd_vma hi_sec_off;
  riscv_pcgp_lo_reloc *next;
};

typedef struct
{
  riscv_pcgp_hi_reloc *hi;
  riscv_pcgp_lo_reloc *lo;
} riscv_pcgp_relocs;

/* Initialize the pcgp reloc info in P.  */

static bfd_boolean
riscv_init_pcgp_relocs (riscv_pcgp_relocs *p)
{
  p->hi = NULL;
  p->lo = NULL;
  return TRUE;
}

/* Free the pcgp reloc info in P.  */

static void
riscv_free_pcgp_relocs (riscv_pcgp_relocs *p,
			bfd *abfd ATTRIBUTE_UNUSED,
			asection *sec ATTRIBUTE_UNUSED)
{
  riscv_pcgp_hi_reloc *c;
  riscv_pcgp_lo_reloc *l;

  for (c = p->hi; c != NULL;)
    {
      riscv_pcgp_hi_reloc *next = c->next;
      free (c);
      c = next;
    }

  for (l = p->lo; l != NULL;)
    {
      riscv_pcgp_lo_reloc *next = l->next;
      free (l);
      l = next;
    }
}

/* Record pcgp hi part reloc info in P, using HI_SEC_OFF as the lookup index.
   The HI_ADDEND, HI_ADDR, HI_SYM, and SYM_SEC args contain info required to
   relax the corresponding lo part reloc.  */

static bfd_boolean
riscv_record_pcgp_hi_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off,
			    bfd_vma hi_addend, bfd_vma hi_addr,
			    unsigned hi_sym, asection *sym_sec,
			    bfd_boolean undefined_weak)
{
  riscv_pcgp_hi_reloc *new = bfd_malloc (sizeof(*new));
  if (!new)
    return FALSE;
  new->hi_sec_off = hi_sec_off;
  new->hi_addend = hi_addend;
  new->hi_addr = hi_addr;
  new->hi_sym = hi_sym;
  new->sym_sec = sym_sec;
  new->undefined_weak = undefined_weak;
  new->next = p->hi;
  p->hi = new;
  return TRUE;
}

/* Look up hi part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a lo part reloc to find the corresponding hi part reloc.  */

static riscv_pcgp_hi_reloc *
riscv_find_pcgp_hi_reloc(riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_hi_reloc *c;

  for (c = p->hi; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return c;
  return NULL;
}

/* Record pcgp lo part reloc info in P, using HI_SEC_OFF as the lookup info.
   This is used to record relocs that can't be relaxed.  */

static bfd_boolean
riscv_record_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *new = bfd_malloc (sizeof(*new));
  if (!new)
    return FALSE;
  new->hi_sec_off = hi_sec_off;
  new->next = p->lo;
  p->lo = new;
  return TRUE;
}

/* Look up lo part pcgp reloc info in P, using HI_SEC_OFF as the lookup index.
   This is used by a hi part reloc to find the corresponding lo part reloc.  */

static bfd_boolean
riscv_find_pcgp_lo_reloc (riscv_pcgp_relocs *p, bfd_vma hi_sec_off)
{
  riscv_pcgp_lo_reloc *c;

  for (c = p->lo; c != NULL; c = c->next)
    if (c->hi_sec_off == hi_sec_off)
      return TRUE;
  return FALSE;
}

typedef bfd_boolean (*relax_func_t) (bfd *, asection *, asection *,
				     struct bfd_link_info *,
				     Elf_Internal_Rela *,
				     bfd_vma, bfd_vma, bfd_vma, bfd_boolean *,
				     riscv_pcgp_relocs *,
				     bfd_boolean undefined_weak);

/* Relax AUIPC + JALR into JAL.  */

static bfd_boolean
_bfd_riscv_relax_call (bfd *abfd, asection *sec, asection *sym_sec,
		       struct bfd_link_info *link_info,
		       Elf_Internal_Rela *rel,
		       bfd_vma symval,
		       bfd_vma max_alignment,
		       bfd_vma reserve_size ATTRIBUTE_UNUSED,
		       bfd_boolean *again,
		       riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
		       bfd_boolean undefined_weak ATTRIBUTE_UNUSED)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_signed_vma foff = symval - (sec_addr (sec) + rel->r_offset);
  bfd_boolean near_zero = (symval + RISCV_IMM_REACH/2) < RISCV_IMM_REACH;
  bfd_vma auipc, jalr;
  int rd, r_type, len = 4, rvc = elf_elfheader (abfd)->e_flags & EF_RISCV_RVC;

  /* If the call crosses section boundaries, an alignment directive could
     cause the PC-relative offset to later increase, so we need to add in the
     max alignment of any section inclusive from the call to the target.
     Otherwise, we only need to use the alignment of the current section.  */
  if (VALID_UJTYPE_IMM (foff))
    {
      if (sym_sec->output_section == sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
      foff += (foff < 0 ? -max_alignment : max_alignment);
    }

  /* See if this function call can be shortened.  */
  if (!VALID_UJTYPE_IMM (foff) && !(!bfd_link_pic (link_info) && near_zero))
    return TRUE;

  /* Shorten the function call.  */
  BFD_ASSERT (rel->r_offset + 8 <= sec->size);

  auipc = bfd_get_32 (abfd, contents + rel->r_offset);
  jalr = bfd_get_32 (abfd, contents + rel->r_offset + 4);
  rd = (jalr >> OP_SH_RD) & OP_MASK_RD;
  rvc = rvc && VALID_RVC_J_IMM (foff);

  /* C.J exists on RV32 and RV64, but C.JAL is RV32-only.  */
  rvc = rvc && (rd == 0 || (rd == X_RA && ARCH_SIZE == 32));

  if (rvc)
    {
      /* Relax to C.J[AL] rd, addr.  */
      r_type = R_RISCV_RVC_JUMP;
      auipc = rd == 0 ? MATCH_C_J : MATCH_C_JAL;
      len = 2;
    }
  else if (VALID_UJTYPE_IMM (foff))
    {
      /* Relax to JAL rd, addr.  */
      r_type = R_RISCV_JAL;
      auipc = MATCH_JAL | (rd << OP_SH_RD);
    }
  else /* near_zero */
    {
      /* Relax to JALR rd, x0, addr.  */
      r_type = R_RISCV_LO12_I;
      auipc = MATCH_JALR | (rd << OP_SH_RD);
    }

  /* Replace the R_RISCV_CALL reloc.  */
  rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), r_type);
  /* Replace the AUIPC.  */
  bfd_put (8 * len, abfd, auipc, contents + rel->r_offset);

  /* Delete unnecessary JALR.  */
  *again = TRUE;
  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + len, 8 - len,
				   link_info);
}

/* Traverse all output sections and return the max alignment.  */

static bfd_vma
_bfd_riscv_get_max_alignment (asection *sec)
{
  unsigned int max_alignment_power = 0;
  asection *o;

  for (o = sec->output_section->owner->sections; o != NULL; o = o->next)
    {
      if (o->alignment_power > max_alignment_power)
	max_alignment_power = o->alignment_power;
    }

  return (bfd_vma) 1 << max_alignment_power;
}

/* Relax non-PIC global variable references.  */

static bfd_boolean
_bfd_riscv_relax_lui (bfd *abfd,
		      asection *sec,
		      asection *sym_sec,
		      struct bfd_link_info *link_info,
		      Elf_Internal_Rela *rel,
		      bfd_vma symval,
		      bfd_vma max_alignment,
		      bfd_vma reserve_size,
		      bfd_boolean *again,
		      riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
		      bfd_boolean undefined_weak)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma gp = riscv_global_pointer_value (link_info);
  int use_rvc = elf_elfheader (abfd)->e_flags & EF_RISCV_RVC;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  if (gp)
    {
      /* If gp and the symbol are in the same output section, which is not the
	 abs section, then consider only that output section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, FALSE, FALSE,
			      TRUE);
      if (h->u.def.section->output_section == sym_sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.  */
  if (undefined_weak
      || (VALID_ITYPE_IMM (symval)
	  || (symval >= gp
	      && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
	  || (symval < gp
	      && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size))))
    {
      unsigned sym = ELFNN_R_SYM (rel->r_info);
      switch (ELFNN_R_TYPE (rel->r_info))
	{
	case R_RISCV_LO12_I:
	  if (undefined_weak)
	    {
	      /* Change the RS1 to zero.  */
	      bfd_vma insn = bfd_get_32 (abfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (abfd, insn, contents + rel->r_offset);
	    }
	  else
	    rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_I);
	  return TRUE;

	case R_RISCV_LO12_S:
	  if (undefined_weak)
	    {
	      /* Change the RS1 to zero.  */
	      bfd_vma insn = bfd_get_32 (abfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (abfd, insn, contents + rel->r_offset);
	    }
	  else
	    rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_S);
	  return TRUE;

	case R_RISCV_HI20:
	  /* We can delete the unnecessary LUI and reloc.  */
	  rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);
	  *again = TRUE;
	  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4,
					   link_info);

	default:
	  abort ();
	}
    }

  /* Can we relax LUI to C.LUI?  Alignment might move the section forward;
     account for this assuming page alignment at worst. In the presence of 
     RELRO segment the linker aligns it by one page size, therefore sections
     after the segment can be moved more than one page. */

  if (use_rvc
      && ELFNN_R_TYPE (rel->r_info) == R_RISCV_HI20
      && VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (symval))
      && VALID_RVC_LUI_IMM (RISCV_CONST_HIGH_PART (symval)
			    + (link_info->relro ? 2 * ELF_MAXPAGESIZE
			       : ELF_MAXPAGESIZE)))
    {
      /* Replace LUI with C.LUI if legal (i.e., rd != x0 and rd != x2/sp).  */
      bfd_vma lui = bfd_get_32 (abfd, contents + rel->r_offset);
      unsigned rd = ((unsigned)lui >> OP_SH_RD) & OP_MASK_RD;
      if (rd == 0 || rd == X_SP)
	return TRUE;

      lui = (lui & (OP_MASK_RD << OP_SH_RD)) | MATCH_C_LUI;
      bfd_put_32 (abfd, lui, contents + rel->r_offset);

      /* Replace the R_RISCV_HI20 reloc.  */
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_RVC_LUI);

      *again = TRUE;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + 2, 2,
				       link_info);
    }

  return TRUE;
}

/* Relax non-PIC TLS references.  */

static bfd_boolean
_bfd_riscv_relax_tls_le (bfd *abfd,
			 asection *sec,
			 asection *sym_sec ATTRIBUTE_UNUSED,
			 struct bfd_link_info *link_info,
			 Elf_Internal_Rela *rel,
			 bfd_vma symval,
			 bfd_vma max_alignment ATTRIBUTE_UNUSED,
			 bfd_vma reserve_size ATTRIBUTE_UNUSED,
			 bfd_boolean *again,
			 riscv_pcgp_relocs *prcel_relocs ATTRIBUTE_UNUSED,
			 bfd_boolean undefined_weak ATTRIBUTE_UNUSED)
{
  /* See if this symbol is in range of tp.  */
  if (RISCV_CONST_HIGH_PART (tpoff (link_info, symval)) != 0)
    return TRUE;

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);
  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_TPREL_LO12_I:
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_TPREL_I);
      return TRUE;

    case R_RISCV_TPREL_LO12_S:
      rel->r_info = ELFNN_R_INFO (ELFNN_R_SYM (rel->r_info), R_RISCV_TPREL_S);
      return TRUE;

    case R_RISCV_TPREL_HI20:
    case R_RISCV_TPREL_ADD:
      /* We can delete the unnecessary instruction and reloc.  */
      rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);
      *again = TRUE;
      return riscv_relax_delete_bytes (abfd, sec, rel->r_offset, 4, link_info);

    default:
      abort ();
    }
}

/* Implement R_RISCV_ALIGN by deleting excess alignment NOPs.  */

static bfd_boolean
_bfd_riscv_relax_align (bfd *abfd, asection *sec,
			asection *sym_sec,
			struct bfd_link_info *link_info,
			Elf_Internal_Rela *rel,
			bfd_vma symval,
			bfd_vma max_alignment ATTRIBUTE_UNUSED,
			bfd_vma reserve_size ATTRIBUTE_UNUSED,
			bfd_boolean *again ATTRIBUTE_UNUSED,
			riscv_pcgp_relocs *pcrel_relocs ATTRIBUTE_UNUSED,
			bfd_boolean undefined_weak ATTRIBUTE_UNUSED)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma alignment = 1, pos;
  while (alignment <= rel->r_addend)
    alignment *= 2;

  symval -= rel->r_addend;
  bfd_vma aligned_addr = ((symval - 1) & ~(alignment - 1)) + alignment;
  bfd_vma nop_bytes = aligned_addr - symval;

  /* Once we've handled an R_RISCV_ALIGN, we can't relax anything else.  */
  sec->sec_flg0 = TRUE;

  /* Make sure there are enough NOPs to actually achieve the alignment.  */
  if (rel->r_addend < nop_bytes)
    {
      _bfd_error_handler
	(_("%pB(%pA+%#" PRIx64 "): %" PRId64 " bytes required for alignment "
	   "to %" PRId64 "-byte boundary, but only %" PRId64 " present"),
	 abfd, sym_sec, (uint64_t) rel->r_offset,
	 (int64_t) nop_bytes, (int64_t) alignment, (int64_t) rel->r_addend);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  /* Delete the reloc.  */
  rel->r_info = ELFNN_R_INFO (0, R_RISCV_NONE);

  /* If the number of NOPs is already correct, there's nothing to do.  */
  if (nop_bytes == rel->r_addend)
    return TRUE;

  /* Write as many RISC-V NOPs as we need.  */
  for (pos = 0; pos < (nop_bytes & -4); pos += 4)
    bfd_put_32 (abfd, RISCV_NOP, contents + rel->r_offset + pos);

  /* Write a final RVC NOP if need be.  */
  if (nop_bytes % 4 != 0)
    bfd_put_16 (abfd, RVC_NOP, contents + rel->r_offset + pos);

  /* Delete the excess bytes.  */
  return riscv_relax_delete_bytes (abfd, sec, rel->r_offset + nop_bytes,
				   rel->r_addend - nop_bytes, link_info);
}

/* Relax PC-relative references to GP-relative references.  */

static bfd_boolean
_bfd_riscv_relax_pc  (bfd *abfd ATTRIBUTE_UNUSED,
		      asection *sec,
		      asection *sym_sec,
		      struct bfd_link_info *link_info,
		      Elf_Internal_Rela *rel,
		      bfd_vma symval,
		      bfd_vma max_alignment,
		      bfd_vma reserve_size,
		      bfd_boolean *again ATTRIBUTE_UNUSED,
		      riscv_pcgp_relocs *pcgp_relocs,
		      bfd_boolean undefined_weak)
{
  bfd_byte *contents = elf_section_data (sec)->this_hdr.contents;
  bfd_vma gp = riscv_global_pointer_value (link_info);

  BFD_ASSERT (rel->r_offset + 4 <= sec->size);

  /* Chain the _LO relocs to their cooresponding _HI reloc to compute the
   * actual target address.  */
  riscv_pcgp_hi_reloc hi_reloc;
  memset (&hi_reloc, 0, sizeof (hi_reloc));
  switch (ELFNN_R_TYPE (rel->r_info))
    {
    case R_RISCV_PCREL_LO12_I:
    case R_RISCV_PCREL_LO12_S:
      {
	/* If the %lo has an addend, it isn't for the label pointing at the
	   hi part instruction, but rather for the symbol pointed at by the
	   hi part instruction.  So we must subtract it here for the lookup.
	   It is still used below in the final symbol address.  */
	bfd_vma hi_sec_off = symval - sec_addr (sym_sec) - rel->r_addend;
	riscv_pcgp_hi_reloc *hi = riscv_find_pcgp_hi_reloc (pcgp_relocs,
							    hi_sec_off);
	if (hi == NULL)
	  {
	    riscv_record_pcgp_lo_reloc (pcgp_relocs, hi_sec_off);
	    return TRUE;
	  }

	hi_reloc = *hi;
	symval = hi_reloc.hi_addr;
	sym_sec = hi_reloc.sym_sec;

	/* We can not know whether the undefined weak symbol is referenced
	   according to the information of R_RISCV_PCREL_LO12_I/S.  Therefore,
	   we have to record the 'undefined_weak' flag when handling the
	   corresponding R_RISCV_HI20 reloc in riscv_record_pcgp_hi_reloc.  */
	undefined_weak = hi_reloc.undefined_weak;
      }
      break;

    case R_RISCV_PCREL_HI20:
      /* Mergeable symbols and code might later move out of range.  */
      if (! undefined_weak
	  && sym_sec->flags & (SEC_MERGE | SEC_CODE))
	return TRUE;

      /* If the cooresponding lo relocation has already been seen then it's not
       * safe to relax this relocation.  */
      if (riscv_find_pcgp_lo_reloc (pcgp_relocs, rel->r_offset))
	return TRUE;

      break;

    default:
      abort ();
    }

  if (gp)
    {
      /* If gp and the symbol are in the same output section, which is not the
	 abs section, then consider only that output section's alignment.  */
      struct bfd_link_hash_entry *h =
	bfd_link_hash_lookup (link_info->hash, RISCV_GP_SYMBOL, FALSE, FALSE,
			      TRUE);
      if (h->u.def.section->output_section == sym_sec->output_section
	  && sym_sec->output_section != bfd_abs_section_ptr)
	max_alignment = (bfd_vma) 1 << sym_sec->output_section->alignment_power;
    }

  /* Is the reference in range of x0 or gp?
     Valid gp range conservatively because of alignment issue.  */
  if (undefined_weak
      || (VALID_ITYPE_IMM (symval)
	  || (symval >= gp
	      && VALID_ITYPE_IMM (symval - gp + max_alignment + reserve_size))
	  || (symval < gp
	      && VALID_ITYPE_IMM (symval - gp - max_alignment - reserve_size))))
    {
      unsigned sym = hi_reloc.hi_sym;
      switch (ELFNN_R_TYPE (rel->r_info))
	{
	case R_RISCV_PCREL_LO12_I:
	  if (undefined_weak)
	    {
	      /* Change the RS1 to zero, and then modify the relocation
		 type to R_RISCV_LO12_I.  */
	      bfd_vma insn = bfd_get_32 (abfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (abfd, insn, contents + rel->r_offset);
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LO12_I);
	      rel->r_addend = hi_reloc.hi_addend;
	    }
	  else
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_I);
	      rel->r_addend += hi_reloc.hi_addend;
	    }
	  return TRUE;

	case R_RISCV_PCREL_LO12_S:
	  if (undefined_weak)
	    {
	      /* Change the RS1 to zero, and then modify the relocation
		 type to R_RISCV_LO12_S.  */
	      bfd_vma insn = bfd_get_32 (abfd, contents + rel->r_offset);
	      insn &= ~(OP_MASK_RS1 << OP_SH_RS1);
	      bfd_put_32 (abfd, insn, contents + rel->r_offset);
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_LO12_S);
	      rel->r_addend = hi_reloc.hi_addend;
	    }
	  else
	    {
	      rel->r_info = ELFNN_R_INFO (sym, R_RISCV_GPREL_S);
	      rel->r_addend += hi_reloc.hi_addend;
	    }
	  return TRUE;

	case R_RISCV_PCREL_HI20:
	  riscv_record_pcgp_hi_reloc (pcgp_relocs,
				      rel->r_offset,
				      rel->r_addend,
				      symval,
				      ELFNN_R_SYM(rel->r_info),
				      sym_sec,
				      undefined_weak);
	  /* We can delete the unnecessary AUIPC and reloc.  */
	  rel->r_info = ELFNN_R_INFO (0, R_RISCV_DELETE);
	  rel->r_addend = 4;
	  return TRUE;

	default:
	  abort ();
	}
    }

  return TRUE;
}

/* Relax PC-relative references to GP-relative references.  */

static bfd_boolean
_bfd_riscv_relax_delete (bfd *abfd,
			 asection *sec,
			 asection *sym_sec ATTRIBUTE_UNUSED,
			 struct bfd_link_info *link_info,
			 Elf_Internal_Rela *rel,
			 bfd_vma symval ATTRIBUTE_UNUSED,
			 bfd_vma max_alignment ATTRIBUTE_UNUSED,
			 bfd_vma reserve_size ATTRIBUTE_UNUSED,
			 bfd_boolean *again ATTRIBUTE_UNUSED,
			 riscv_pcgp_relocs *pcgp_relocs ATTRIBUTE_UNUSED,
			 bfd_boolean undefined_weak ATTRIBUTE_UNUSED)
{
  if (!riscv_relax_delete_bytes(abfd, sec, rel->r_offset, rel->r_addend,
				link_info))
    return FALSE;
  rel->r_info = ELFNN_R_INFO(0, R_RISCV_NONE);
  return TRUE;
}

/* Relax a section.  Pass 0 shortens code sequences unless disabled.  Pass 1
   deletes the bytes that pass 0 made obselete.  Pass 2, which cannot be
   disabled, handles code alignment directives.  */
static bfd_boolean
_bfd_riscv_relax_section (bfd *abfd, asection *sec,
			  struct bfd_link_info *info,
			  bfd_boolean *again)
{
  static bfd_boolean pass0 = FALSE, pass1 = FALSE, pass2 = FALSE;
  if (info->relax_pass == 0 && !pass0) {
    pass0 = TRUE;
    if (riscv_comrv_debug)
      fprintf(stderr, "* _bfd_riscv_relax_section(0)\n");
  }
  if (info->relax_pass == 1 && !pass1) {
    pass1 = TRUE;
    if (riscv_comrv_debug)
      fprintf(stderr, "* _bfd_riscv_relax_section(1)\n");
  }
  if (info->relax_pass == 2 && !pass2) {
    pass2 = TRUE;
    if (riscv_comrv_debug)
      fprintf(stderr, "* _bfd_riscv_relax_section(2)\n");
  }
  Elf_Internal_Shdr *symtab_hdr = &elf_symtab_hdr (abfd);
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  struct bfd_elf_section_data *data = elf_section_data (sec);
  Elf_Internal_Rela *relocs;
  bfd_boolean ret = FALSE;
  unsigned int i;
  bfd_vma max_alignment, reserve_size = 0;
  riscv_pcgp_relocs pcgp_relocs;

  *again = FALSE;

  if (bfd_link_relocatable (info)
      || sec->sec_flg0
      || (sec->flags & SEC_RELOC) == 0
      || sec->reloc_count == 0
      || (info->disable_target_specific_optimizations
	  && info->relax_pass == 0))
    return TRUE;

  riscv_init_pcgp_relocs (&pcgp_relocs);

  /* Read this BFD's relocs if we haven't done so already.  */
  if (data->relocs)
    relocs = data->relocs;
  else if (!(relocs = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
						 info->keep_memory)))
    goto fail;

  if (htab)
    {
      max_alignment = htab->max_alignment;
      if (max_alignment == (bfd_vma) -1)
	{
	  max_alignment = _bfd_riscv_get_max_alignment (sec);
	  htab->max_alignment = max_alignment;
	}
    }
  else
    max_alignment = _bfd_riscv_get_max_alignment (sec);

  /* Examine and consider relaxing each reloc.  */
  for (i = 0; i < sec->reloc_count; i++)
    {
      asection *sym_sec;
      Elf_Internal_Rela *rel = relocs + i;
      relax_func_t relax_func;
      int type = ELFNN_R_TYPE (rel->r_info);
      bfd_vma symval;
      char symtype;
      bfd_boolean undefined_weak = FALSE;

      relax_func = NULL;
      if (info->relax_pass == 0)
	{
	  if (type == R_RISCV_CALL || type == R_RISCV_CALL_PLT)
	    relax_func = _bfd_riscv_relax_call;
	  else if (type == R_RISCV_HI20
		   || type == R_RISCV_LO12_I
		   || type == R_RISCV_LO12_S)
	    relax_func = _bfd_riscv_relax_lui;
	  else if (!bfd_link_pic(info)
		   && (type == R_RISCV_PCREL_HI20
		   || type == R_RISCV_PCREL_LO12_I
		   || type == R_RISCV_PCREL_LO12_S))
	    relax_func = _bfd_riscv_relax_pc;
	  else if (type == R_RISCV_TPREL_HI20
		   || type == R_RISCV_TPREL_ADD
		   || type == R_RISCV_TPREL_LO12_I
		   || type == R_RISCV_TPREL_LO12_S)
	    relax_func = _bfd_riscv_relax_tls_le;
	  else
	    continue;

	  /* Only relax this reloc if it is paired with R_RISCV_RELAX.  */
	  if (i == sec->reloc_count - 1
	      || ELFNN_R_TYPE ((rel + 1)->r_info) != R_RISCV_RELAX
	      || rel->r_offset != (rel + 1)->r_offset)
	    continue;

	  /* Skip over the R_RISCV_RELAX.  */
	  i++;
	}
      else if (info->relax_pass == 1 && type == R_RISCV_DELETE)
	relax_func = _bfd_riscv_relax_delete;
      else if (info->relax_pass == 2 && type == R_RISCV_ALIGN)
	relax_func = _bfd_riscv_relax_align;
      else
	continue;

      data->relocs = relocs;

      /* Read this BFD's contents if we haven't done so already.  */
      if (!data->this_hdr.contents
	  && !bfd_malloc_and_get_section (abfd, sec, &data->this_hdr.contents))
	goto fail;

      /* Read this BFD's symbols if we haven't done so already.  */
      if (symtab_hdr->sh_info != 0
	  && !symtab_hdr->contents
	  && !(symtab_hdr->contents =
	       (unsigned char *) bfd_elf_get_elf_syms (abfd, symtab_hdr,
						       symtab_hdr->sh_info,
						       0, NULL, NULL, NULL)))
	goto fail;

      /* Get the value of the symbol referred to by the reloc.  */
      if (ELFNN_R_SYM (rel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  Elf_Internal_Sym *isym = ((Elf_Internal_Sym *) symtab_hdr->contents
				    + ELFNN_R_SYM (rel->r_info));
	  reserve_size = (isym->st_size - rel->r_addend) > isym->st_size
	    ? 0 : isym->st_size - rel->r_addend;

	  if (isym->st_shndx == SHN_UNDEF)
	    sym_sec = sec, symval = rel->r_offset;
	  else
	    {
	      BFD_ASSERT (isym->st_shndx < elf_numsections (abfd));
	      sym_sec = elf_elfsections (abfd)[isym->st_shndx]->bfd_section;
#if 0
	      /* The purpose of this code is unknown.  It breaks linker scripts
		 for embedded development that place sections at address zero.
		 This code is believed to be unnecessary.  Disabling it but not
		 yet removing it, in case something breaks.  */
	      if (sec_addr (sym_sec) == 0)
		continue;
#endif
	      symval = isym->st_value;
	    }
	  symtype = ELF_ST_TYPE (isym->st_info);
	}
      else
	{
	  unsigned long indx;
	  struct elf_link_hash_entry *h;

	  indx = ELFNN_R_SYM (rel->r_info) - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];

	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;

	  if (h->root.type == bfd_link_hash_undefweak
	      && (relax_func == _bfd_riscv_relax_lui
		  || relax_func == _bfd_riscv_relax_pc))
	    {
	      /* For the lui and auipc relaxations, since the symbol
		 value of an undefined weak symbol is always be zero,
		 we can optimize the patterns into a single LI/MV/ADDI
		 instruction.

		 Note that, creating shared libraries and pie output may
		 break the rule above.  Fortunately, since we do not relax
		 pc relocs when creating shared libraries and pie output,
		 and the absolute address access for R_RISCV_HI20 isn't
		 allowed when "-fPIC" is set, the problem of creating shared
		 libraries can not happen currently.  Once we support the
		 auipc relaxations when creating shared libraries, then we will
		 need the more rigorous checking for this optimization.  */
	      undefined_weak = TRUE;
	    }

	  /* This line has to match the check in riscv_elf_relocate_section
	     in the R_RISCV_CALL[_PLT] case.  */
	  if (bfd_link_pic (info) && h->plt.offset != MINUS_ONE)
	    {
	      sym_sec = htab->elf.splt;
	      symval = h->plt.offset;
	    }
	  else if (undefined_weak)
	    {
	      symval = 0;
	      sym_sec = bfd_und_section_ptr;
	    }
	  else if (h->root.u.def.section->output_section == NULL
		   || (h->root.type != bfd_link_hash_defined
		       && h->root.type != bfd_link_hash_defweak))
	    continue;
	  else
	    {
	      symval = h->root.u.def.value;
	      sym_sec = h->root.u.def.section;
	    }

	  if (h->type != STT_FUNC)
	    reserve_size =
	      (h->size - rel->r_addend) > h->size ? 0 : h->size - rel->r_addend;
	  symtype = h->type;
	}

      if (sym_sec->sec_info_type == SEC_INFO_TYPE_MERGE
          && (sym_sec->flags & SEC_MERGE))
	{
	  /* At this stage in linking, no SEC_MERGE symbol has been
	     adjusted, so all references to such symbols need to be
	     passed through _bfd_merged_section_offset.  (Later, in
	     relocate_section, all SEC_MERGE symbols *except* for
	     section symbols have been adjusted.)

	     gas may reduce relocations against symbols in SEC_MERGE
	     sections to a relocation against the section symbol when
	     the original addend was zero.  When the reloc is against
	     a section symbol we should include the addend in the
	     offset passed to _bfd_merged_section_offset, since the
	     location of interest is the original symbol.  On the
	     other hand, an access to "sym+addend" where "sym" is not
	     a section symbol should not include the addend;  Such an
	     access is presumed to be an offset from "sym";  The
	     location of interest is just "sym".  */
	   if (symtype == STT_SECTION)
	     symval += rel->r_addend;

	   symval = _bfd_merged_section_offset (abfd, &sym_sec,
						elf_section_data (sym_sec)->sec_info,
						symval);

	   if (symtype != STT_SECTION)
	     symval += rel->r_addend;
	}
      else
	symval += rel->r_addend;

      symval += sec_addr (sym_sec);

      if (!relax_func (abfd, sec, sym_sec, info, rel, symval,
		       max_alignment, reserve_size, again,
		       &pcgp_relocs, undefined_weak))
	goto fail;
    }

  ret = TRUE;

 fail:
  if (relocs != data->relocs)
    free (relocs);
  riscv_free_pcgp_relocs(&pcgp_relocs, abfd, sec);

  return ret;
}

#if ARCH_SIZE == 32
# define PRSTATUS_SIZE			204
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		24
# define PRSTATUS_OFFSET_PR_REG		72
# define ELF_GREGSET_T_SIZE		128
# define PRPSINFO_SIZE			128
# define PRPSINFO_OFFSET_PR_PID		16
# define PRPSINFO_OFFSET_PR_FNAME	32
# define PRPSINFO_OFFSET_PR_PSARGS	48
#else
# define PRSTATUS_SIZE			376
# define PRSTATUS_OFFSET_PR_CURSIG	12
# define PRSTATUS_OFFSET_PR_PID		32
# define PRSTATUS_OFFSET_PR_REG		112
# define ELF_GREGSET_T_SIZE		256
# define PRPSINFO_SIZE			136
# define PRPSINFO_OFFSET_PR_PID		24
# define PRPSINFO_OFFSET_PR_FNAME	40
# define PRPSINFO_OFFSET_PR_PSARGS	56
#endif

/* Write PRSTATUS note into core file.  */

static char *
riscv_write_core_note (bfd *abfd, char *buf, int *bufsiz, int note_type,
                       ...)
{
  switch (note_type)
    {
    default:
      return NULL;

    case NT_PRPSINFO:
      BFD_FAIL ();
      return NULL;

    case NT_PRSTATUS:
      {
        char data[PRSTATUS_SIZE];
        va_list ap;
        long pid;
        int cursig;
        const void *greg;

        va_start (ap, note_type);
        memset (data, 0, sizeof(data));
        pid = va_arg (ap, long);
        bfd_put_32 (abfd, pid, data + PRSTATUS_OFFSET_PR_PID);
        cursig = va_arg (ap, int);
        bfd_put_16 (abfd, cursig, data + PRSTATUS_OFFSET_PR_CURSIG);
        greg = va_arg (ap, const void *);
        memcpy (data + PRSTATUS_OFFSET_PR_REG, greg,
                PRSTATUS_SIZE - PRSTATUS_OFFSET_PR_REG - ARCH_SIZE / 8);
        va_end (ap);
        return elfcore_write_note (abfd, buf, bufsiz,
                                   "CORE", note_type, data, sizeof (data));
      }
    }
}

/* Support for core dump NOTE sections.  */

static bfd_boolean
riscv_elf_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return FALSE;

      case PRSTATUS_SIZE:  /* sizeof(struct elf_prstatus) on Linux/RISC-V.  */
	/* pr_cursig */
	elf_tdata (abfd)->core->signal
	  = bfd_get_16 (abfd, note->descdata + PRSTATUS_OFFSET_PR_CURSIG);

	/* pr_pid */
	elf_tdata (abfd)->core->lwpid
	  = bfd_get_32 (abfd, note->descdata + PRSTATUS_OFFSET_PR_PID);
	break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg", ELF_GREGSET_T_SIZE,
					  note->descpos + PRSTATUS_OFFSET_PR_REG);
}

static bfd_boolean
riscv_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return FALSE;

      case PRPSINFO_SIZE: /* sizeof(struct elf_prpsinfo) on Linux/RISC-V.  */
	/* pr_pid */
	elf_tdata (abfd)->core->pid
	  = bfd_get_32 (abfd, note->descdata + PRPSINFO_OFFSET_PR_PID);

	/* pr_fname */
	elf_tdata (abfd)->core->program = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_FNAME, 16);

	/* pr_psargs */
	elf_tdata (abfd)->core->command = _bfd_elfcore_strndup
	  (abfd, note->descdata + PRPSINFO_OFFSET_PR_PSARGS, 80);
	break;
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return TRUE;
}

/* Set the right mach type.  */
static bfd_boolean
riscv_elf_object_p (bfd *abfd)
{
  /* There are only two mach types in RISCV currently.  */
  if (strcmp (abfd->xvec->name, "elf32-littleriscv") == 0)
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv32);
  else
    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv64);

  return TRUE;
}

static bfd_boolean
riscv_elf_create_ovl_dup_symbol (struct bfd_link_info *info, const char *name,
				 bfd_vma group, asection *s, bfd_vma size)
{
  char *symbol_name;
  symbol_name = malloc(15 + strlen(name));
  struct bfd_link_hash_entry *bfdh;
  struct elf_link_hash_entry *elfh;
  bfd_boolean res;

  sprintf (symbol_name, "%s$group%lu", name, group);

  /* Create a new symbol */
  bfdh = NULL;
  res = _bfd_generic_link_add_one_symbol (info, s->owner, symbol_name,
					  BSF_GLOBAL, s, size, NULL, TRUE,
					  FALSE, &bfdh);
  free(symbol_name);
  if (!res)
    return FALSE;

  /* Set ELF flags */
  elfh = (struct elf_link_hash_entry *)bfdh;
  elfh->type = ELF_ST_INFO (STB_GLOBAL, STT_FUNC);
  elfh->size = size;
  return TRUE;
}

/* Determine whether an object attribute tag takes an integer, a
   string or both.  */

static int
riscv_elf_obj_attrs_arg_type (int tag)
{
  return (tag & 1) != 0 ? ATTR_TYPE_FLAG_STR_VAL : ATTR_TYPE_FLAG_INT_VAL;
}

/* This function is called by the LDEMUL_AFTER_CHECK_RELOCS hook.  */
void riscv_elf_overlay_hook_elfNNlriscv(struct bfd_link_info *info);
void
riscv_elf_overlay_hook_elfNNlriscv(struct bfd_link_info *info)
{
  if (riscv_comrv_debug)
    fprintf(stderr, "* do_overlay_stuff_elfNNlriscv\n");
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);

  if (!htab->overlay_enabled || htab->elf.dynobj == NULL)
    return;

  const struct elf_backend_data *bed = get_elf_backend_data (htab->elf.dynobj);

  riscv_elf_overlay_preprocess (info->output_bfd, info);

  /* For group 0, create a special input section that will hold the
     group table and multigroup table.  */
  {
    flagword flags;
    asection *s;
    bfd_vma size = htab->ovl_group_table_size + htab->ovl_multigroup_table_size;

    flags = bed->dynamic_sec_flags | SEC_READONLY | SEC_CODE;
    s = bfd_make_section_anyway_with_flags (htab->elf.dynobj,
                                            ".ovlinput.__internal.grouptables",
                                            flags);
    BFD_ASSERT(s != NULL);
    s->contents = (unsigned char *)bfd_zalloc (htab->elf.dynobj, size);
    s->size = size;

    /* Add symbols for the start of the group table, and a symbol
       for the start of the multigroup table (which will be populated
       later).  */
    bfd_boolean res;
    struct bfd_link_hash_entry *bfdh;
    struct elf_link_hash_entry *elfh;

    bfdh = NULL;
    res = _bfd_generic_link_add_one_symbol (info, htab->elf.dynobj,
					    "__OVERLAY_GROUP_TABLE_START",
					    BSF_GLOBAL, s,
					    0, NULL, TRUE, FALSE, &bfdh);
    BFD_ASSERT(res != FALSE);
    /* Set ELF flags */
    elfh = (struct elf_link_hash_entry *)bfdh;
    elfh->type = ELF_ST_INFO (STB_GLOBAL, STT_OBJECT);
    elfh->size = htab->ovl_group_table_size;

    bfdh = NULL;
    res = _bfd_generic_link_add_one_symbol (info, htab->elf.dynobj,
					    "__OVERLAY_MULTIGROUP_TABLE_START",
					    BSF_GLOBAL, s,
					    htab->ovl_group_table_size,
					    NULL, TRUE, FALSE, &bfdh);
    BFD_ASSERT(res != FALSE);
    elfh = (struct elf_link_hash_entry *)bfdh;
    elfh->type = ELF_ST_INFO (STB_GLOBAL, STT_OBJECT);
    elfh->size = htab->ovl_multigroup_table_size;

    bfdh = NULL;
    res = _bfd_generic_link_add_one_symbol (info, htab->elf.dynobj,
					    "__OVERLAY_MULTIGROUP_TABLE_END",
					    BSF_GLOBAL, s,
					    htab->ovl_group_table_size + htab->ovl_multigroup_table_size,
					    NULL, TRUE, FALSE, &bfdh);
    BFD_ASSERT(res != FALSE);
    elfh = (struct elf_link_hash_entry *)bfdh;
    elfh->type = ELF_ST_INFO (STB_GLOBAL, STT_OBJECT);
    elfh->size = 0;
  }

  /* Create duplicate sections for functions in multigroups.  */
  bfd *ibfd;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      unsigned int i, symcount;
      Elf_Internal_Shdr *symtab_hdr;
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);

      if (! is_riscv_elf (ibfd))
	continue;

      symtab_hdr = &elf_symtab_hdr (ibfd);
      symcount = ((symtab_hdr->sh_size / sizeof (ElfNN_External_Sym))
	          - symtab_hdr->sh_info);

      for (i = 0; i < symcount; i++)
	{
	  flagword flags;
	  struct elf_link_hash_entry *h = sym_hashes[i];
	  asection *sec = h->root.u.def.section;
	  flags = bed->dynamic_sec_flags | SEC_READONLY | SEC_CODE;

	  /* A symbol in an overlay group will be in a section with a
	     name of the format .ovlinput.<symbol name>.  */
	  if (strncmp (sec->name, ".ovlinput.", strlen(".ovlinput.")) != 0)
	    continue;
	  const char *sym_name = sec->name + strlen(".ovlinput.");

	  /* Lookup all of the groups that this symbol exists in.  */
	  struct ovl_func_hash_entry *sym_groups =
	      ovl_func_hash_lookup (&htab->ovl_func_table, sym_name, FALSE,
	                            FALSE);
	  if (sym_groups == NULL)
	    continue;

	  /* For all but the first group in this list, create a duplicate
	     section for that group based on the name.  */
	  char duplicate_func_name[200];
	  struct ovl_func_group_info *func_group_info;
	  BFD_ASSERT(sym_groups->groups != NULL);
	  for (func_group_info = sym_groups->groups->next;
	       func_group_info != NULL;
	       func_group_info = func_group_info->next)
	    {
	      asection *s;
	      sprintf (duplicate_func_name,
		       ".ovlinput.__internal.duplicate.%lu.%s",
		       func_group_info->id, sym_name);

	      /* Don't create the same duplicate section more than once.  */
	      if (bfd_get_section_by_name (htab->elf.dynobj,
	                                   duplicate_func_name))
		continue;

	      if (riscv_comrv_debug)
		fprintf (stderr,
		         "- Creating duplicate section `%s` with size 0x%lx\n",
		         duplicate_func_name, sec->size);

	      s = bfd_make_section_anyway_with_flags (htab->elf.dynobj,
						      strdup(duplicate_func_name),
						      flags);
	      BFD_ASSERT(s != NULL);
	      bfd_set_section_alignment (s, bed->s->log_file_align);
	      s->contents = (unsigned char *)bfd_zalloc (htab->elf.dynobj,
							 sec->size);
	      s->size = sec->size;
	      /* Create a symbol for this duplicate.  */
	      riscv_elf_create_ovl_dup_symbol (info, sym_name,
					       func_group_info->id,
					       s, /* FIXME: Size (relax) */ 0);
	    }
	}
    }

  /* For each group, create an padding section that will hold the group number
     and SHA.  */
  for (unsigned i = 0; i <= ovl_max_group; i++)
    {
      struct ovl_group_list_entry *group_list_entry =
          ovl_group_list_lookup (&htab->ovl_group_list, i, FALSE);
      if (group_list_entry)
	{
	  /* Get the first input section allocated to this group and set
	     its alignment to 512 bytes.  */
	  if (group_list_entry->n_functions != 0 && group_list_entry->first_func)
	    {
	      char *input_sec_name;
	      char *duplicate_sec_name;
	      input_sec_name = malloc(12 + strlen(group_list_entry->first_func));
	      duplicate_sec_name = malloc(40 + strlen(group_list_entry->first_func));

	      sprintf (input_sec_name, ".ovlinput.%s", group_list_entry->first_func);
	      sprintf (duplicate_sec_name, ".ovlinput.__internal.duplicate.%u.%s",
		       i, group_list_entry->first_func);

	      /* First look for a duplicate, if one is not found, then it is the
		 original verison.  */
	      asection *isec = bfd_get_section_by_name (htab->elf.dynobj,
							duplicate_sec_name);
	      if (isec == NULL)
		for (ibfd = info->input_bfds; isec == NULL && ibfd != NULL;
		     ibfd = ibfd->link.next)
		  isec = bfd_get_section_by_name (ibfd, input_sec_name);

	      free(input_sec_name);
	      free(duplicate_sec_name);

	      if (!isec)
		continue;

	      if (riscv_comrv_debug)
		fprintf(stderr, "* Setting '%s' in '%s' to 512byte alignment.\n",
		        isec->name, isec->owner->filename);

	      bfd_set_section_alignment (isec, 9); /* 512 alignment.  */
	    }

	  flagword flags;
	  asection *s;
	  bfd_vma padding = group_list_entry->padded_group_size -
	    group_list_entry->group_size;

	  /* It should be the case that there is always padding for the group
	     SHA?  */
	  BFD_ASSERT(padding > 0);
	  char group_sec_name[40];
	  sprintf (group_sec_name, ".ovlinput.__internal.padding.%u", i);

	  if (riscv_comrv_debug)
	    fprintf (stderr, "- Creating padding section `%s` with size %lx\n",
	             group_sec_name, padding);

	  flags = bed->dynamic_sec_flags | SEC_READONLY | SEC_CODE;
	  s = bfd_make_section_anyway_with_flags (htab->elf.dynobj,
						  strdup(group_sec_name),
						  flags);
	  s->size = padding;
	  s->contents = bfd_zalloc (htab->elf.dynobj, 512);
	  BFD_ASSERT(s != NULL);
	  bfd_set_section_alignment (s, 0);
	}
    }
}

/* Function to determine sorting of input sections when being placed. For
   overlay functions, return the offset of that section in the output.
   NOTE: Due to how the linker uses this value, this function has to return
         a *NEGATIVE* offset in order to sort correctly. */
static int
riscv_elf_overlay_sort_value (asection *s, struct bfd_link_info *info)
{
  struct riscv_elf_link_hash_table *htab = riscv_elf_hash_table (info);
  BFD_ASSERT (s != NULL);
  BFD_ASSERT (htab != NULL);

  /* If this is not an overlay function, return 1.  */
  if (strncmp(s->name, ".ovlinput.", strlen(".ovlinput.")) != 0)
    return 1;

  /* If this is the group table, it will always be the first thing
     to appear in the output section.  */
  if (strncmp(s->name, ".ovlinput.__internal.grouptables",
              strlen(".ovlinput.__internal.grouptables")) == 0)
    {
      /* The group tables are always the first things to appear in the
         output section.  */
      return 0;
    }

  /* If this is an internal padding value, look at the group number, and use
     its offset to return an offset.  */
  if (strncmp(s->name, ".ovlinput.__internal.padding.",
              strlen(".ovlinput.__internal.padding.")) == 0)
    {
      const char *group_id_str = s->name +
          strlen(".ovlinput.__internal.padding.");

      int group_id = atoi (group_id_str);
      struct ovl_group_list_entry *group_list_entry =
          ovl_group_list_lookup (&htab->ovl_group_list, group_id, FALSE);
      BFD_ASSERT(group_list_entry != NULL);

      bfd_vma padding_offset = group_list_entry->group_size;

      if (riscv_comrv_debug)
	fprintf(stderr, " - Offset of %s is %lx\n", s->name,
	        group_list_entry->ovlgrpdata_offset + padding_offset);

      return -(group_list_entry->ovlgrpdata_offset + padding_offset);
    }

  /* If this is a duplicate of a function, look up its symbol hash and find the
     offset corresponding to that group, otherwise it must be the first entry. */
  struct ovl_func_group_info *func_group_info = NULL;
  if (strncmp(s->name, ".ovlinput.__internal.duplicate.",
              strlen(".ovlinput.__internal.duplicate.")) == 0)
    {
      const char *name_and_group = s->name +
          strlen(".ovlinput.__internal.duplicate.");
      const char *sym_name = strchr(name_and_group, '.') + 1;
      BFD_ASSERT(sym_name != (char *)1);
      bfd_vma group_id;
      int matched = sscanf(name_and_group, "%lu.", &group_id);
      BFD_ASSERT(matched = 1);

      struct ovl_func_hash_entry *sym_groups =
          ovl_func_hash_lookup (&htab->ovl_func_table, sym_name, FALSE, FALSE);
      BFD_ASSERT(sym_groups != NULL);
      BFD_ASSERT(sym_groups->groups != NULL);

      /* Start with the second group info, since the first one cannot be a
         duplicate.  */
      for (func_group_info = sym_groups->groups->next;
	   func_group_info != NULL;
	   func_group_info = func_group_info->next)
	{
	  if (func_group_info->id == group_id)
	    break;
	}
    }
  else
    {
      /* Future proof against further internal types.  */
      BFD_ASSERT(strncmp(s->name, ".ovlinput.__internal.",
                         strlen(".ovlinput.__internal.")) != 0);

      /* Return an offset of 0 for functions that have been GC'd.  */
      if (comrv_use_gcmark && !s->gc_mark)
        return 0;

      const char *sym_name = s->name + strlen(".ovlinput.");

      /* This is not a duplicate, therefore it is the first group in the list.*/
      struct ovl_func_hash_entry *sym_groups =
          ovl_func_hash_lookup (&htab->ovl_func_table, sym_name, FALSE, FALSE);
      BFD_ASSERT(sym_groups != NULL);
      BFD_ASSERT(sym_groups->groups != NULL);
      func_group_info = sym_groups->groups;
    }

  BFD_ASSERT(func_group_info != NULL);

  /* func_group_info holds current group and offset, need to find full offset. */
  struct ovl_group_list_entry *group_list_entry =
      ovl_group_list_lookup (&htab->ovl_group_list, func_group_info->id, FALSE);
  BFD_ASSERT(group_list_entry != NULL);

  bfd_vma offset = group_list_entry->ovlgrpdata_offset +
		   func_group_info->unrelaxed_offset;

  if (riscv_comrv_debug)
    fprintf(stderr, " - Offset of %s is %lx\n", s->name, offset);

  return -offset;
}

/* Print one thunk entry for mapfile.  */
struct thunk_for_func_data
{
  bfd_vma target_offset;
  bfd_vma plt_start_addr;
  FILE *mapfile;
};

static bfd_boolean
map_print_think_for_func (struct ovl_func_hash_entry *entry,
                          void *info)
{
  struct thunk_for_func_data *data = info;

  if (entry->plt_entry && entry->plt_offset == data->target_offset)
    {
      bfd_vma entry_addr = data->plt_start_addr + data->target_offset;
      bfd_vma end_addr = entry_addr + OVLPLT_ENTRY_SIZE;
      bfd_vma size = OVLPLT_ENTRY_SIZE;
      fprintf (data->mapfile, "%-20s [%08lx-%08lx)  %08lx\n",
               entry->root.string, entry_addr, end_addr, size);
      return FALSE;
    }

  return TRUE;
}

/* Print state of overlay system to mapfile.  */
void
riscv_elf_overlay_printmap_elfNNlriscv(bfd *obfd,
                                       struct bfd_link_info *info,
                                       FILE *mapfile);
void
riscv_elf_overlay_printmap_elfNNlriscv(bfd *obfd,
                                       struct bfd_link_info *info,
                                       FILE *mapfile)
{
  struct riscv_elf_link_hash_table *htab;
  asection *ovldata_sec;

  htab = riscv_elf_hash_table (info);
  BFD_ASSERT (htab != NULL);
  if (htab->elf.dynobj == NULL)
    return;
  ovldata_sec = bfd_get_section_by_name (obfd, ".ovlgrps");
  if (ovldata_sec == NULL)
    return;

  fprintf (mapfile, "\nOverlay summary\n\n");
  fprintf (mapfile, "GROUP        START    END        LENGTH\n");

  for (unsigned g_id = 0; g_id <= ovl_max_group; g_id++)
    {
      bfd_vma start_addr, end_addr, size;
      struct ovl_group_list_entry *group =
	ovl_group_list_lookup (&htab->ovl_group_list, g_id, FALSE);
      if (!group)
	continue;

      start_addr = ovldata_sec->vma + group->ovlgrpdata_offset;
      end_addr = start_addr + group->padded_group_size;
      size = group->padded_group_size;

      /* groups, virtual address */
      fprintf (mapfile, "Group %-4i  [%8lx-%8lx)  %08lx\n", g_id, start_addr,
	       end_addr, size);

      /* functions (+ (global offset?) + token) */
      for (int i = 0; i < group->n_functions; i++)
	{
	  const char *function = group->functions[i];
	  struct ovl_func_hash_entry *func =
	    ovl_func_hash_lookup (&htab->ovl_func_table, function, FALSE, FALSE);
	  BFD_ASSERT (func != NULL);
	  struct ovl_func_group_info *func_instance = func->groups;
	  while (func_instance != NULL && func_instance->id != g_id)
	    func_instance = func_instance->next;
	  BFD_ASSERT (func_instance != NULL);
	  /* Assert that if we are reporting an offset we have the post-relax
	     value.  */
	  if (func_instance->unrelaxed_offset != 0)
	    BFD_ASSERT (func_instance->processed_offset != 0);

	  uint32_t token;
	  /* If this is a multigroup token, use the cached value, but zero out the
	     plt bit.  */
	  if (func->multigroup)
	    token = func->multigroup_token & 0xf7ffffffU;
	  else
	    token = ovltoken (0, 0, func_instance->processed_offset / 4, g_id);

	  fprintf (mapfile, "  > %8lx: %-20s (token %08x",
		   func_instance->processed_offset + start_addr, function, token);

	  if (func->multigroup)
	    fprintf (mapfile, ", multigroup");
	  fprintf (mapfile, ")\n");
	}

      /* padding */
      if (group->padded_group_size != group->group_size)
	{
	  bfd_vma padding = group->padded_group_size - group->group_size - OVL_CRC_SZ;
	  fprintf (mapfile, "  Padding (before CRC): %li bytes\n", padding);
	}

      /* group CRC */
      fprintf (mapfile, "  CRC: %08x\n", group->crc);
    }

  if (htab->sovlplt)
    {
      struct thunk_for_func_data thunk_data =
	{0, htab->sovlplt->output_section->vma, mapfile};

      fprintf (mapfile, "\nOverlay thunk summary\n\n");
      fprintf (mapfile, "FUNCTION              START    END        LENGTH\n");
      while (thunk_data.target_offset < htab->next_ovlplt_offset)
	{
	  ovl_func_hash_traverse (&htab->ovl_func_table,
				  map_print_think_for_func,
				  &thunk_data);
	  thunk_data.target_offset += OVLPLT_ENTRY_SIZE;
	}
    }
}

#define TARGET_LITTLE_SYM		riscv_elfNN_vec
#define TARGET_LITTLE_NAME		"elfNN-littleriscv"

#define elf_backend_reloc_type_class	     riscv_reloc_type_class

#define bfd_elfNN_bfd_reloc_name_lookup	     riscv_reloc_name_lookup
#define bfd_elfNN_bfd_link_hash_table_create riscv_elf_link_hash_table_create
#define bfd_elfNN_bfd_reloc_type_lookup	     riscv_reloc_type_lookup
#define bfd_elfNN_bfd_merge_private_bfd_data \
  _bfd_riscv_elf_merge_private_bfd_data
#define bfd_elfNN_bfd_get_section_user_sort_data riscv_elf_overlay_sort_value

#define elf_backend_copy_indirect_symbol     riscv_elf_copy_indirect_symbol
#define elf_backend_create_dynamic_sections  riscv_elf_create_dynamic_sections
#define elf_backend_check_relocs	     riscv_elf_check_relocs
#define elf_backend_check_directives         riscv_elf_check_sections
#define elf_backend_adjust_dynamic_symbol    riscv_elf_adjust_dynamic_symbol
#define elf_backend_size_dynamic_sections    riscv_elf_size_dynamic_sections
#define elf_backend_relocate_section	     riscv_elf_relocate_section
#define elf_backend_finish_dynamic_symbol    riscv_elf_finish_dynamic_symbol
#define elf_backend_finish_dynamic_sections  riscv_elf_finish_dynamic_sections
#define elf_backend_gc_mark_hook	     riscv_elf_gc_mark_hook
#define elf_backend_plt_sym_val		     riscv_elf_plt_sym_val
#define elf_backend_grok_prstatus	     riscv_elf_grok_prstatus
#define elf_backend_grok_psinfo		     riscv_elf_grok_psinfo
#define elf_backend_object_p		     riscv_elf_object_p
#undef  elf_backend_write_core_note
#define elf_backend_write_core_note          riscv_write_core_note
#define elf_info_to_howto_rel		     NULL
#define elf_info_to_howto		     riscv_info_to_howto_rela
#define bfd_elfNN_bfd_relax_section	     _bfd_riscv_relax_section

#define elf_backend_init_index_section	     _bfd_elf_init_1_index_section

#define elf_backend_can_gc_sections	1
#define elf_backend_can_refcount	1
#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_plt_alignment	4
#define elf_backend_want_plt_sym	1
#define elf_backend_got_header_size	(ARCH_SIZE / 8)
#define elf_backend_want_dynrelro	1
#define elf_backend_rela_normal		1
#define elf_backend_default_execstack	0

#undef  elf_backend_obj_attrs_vendor
#define elf_backend_obj_attrs_vendor            "riscv"
#undef  elf_backend_obj_attrs_arg_type
#define elf_backend_obj_attrs_arg_type          riscv_elf_obj_attrs_arg_type
#undef  elf_backend_obj_attrs_section_type
#define elf_backend_obj_attrs_section_type      SHT_RISCV_ATTRIBUTES
#undef  elf_backend_obj_attrs_section
#define elf_backend_obj_attrs_section           ".riscv.attributes"

#include "elfNN-target.h"
