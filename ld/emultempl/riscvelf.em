# This shell script emits a C file. -*- C -*-
#   Copyright (C) 2004-2020 Free Software Foundation, Inc.
#
# This file is part of the GNU Binutils.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.

fragment <<EOF

#include "ldmain.h"
#include "ldctor.h"
#include "elf/riscv.h"
#include "elfxx-riscv.h"

extern FILE * riscv_grouping_file;

#define DEFAULT_CRC_INIT   0xffffffff
#define DEFAULT_CRC_POLY   0x04c11db7
#define DEFAULT_CRC_XOROUT 0x00000000
#define DEFAULT_CRC_REFIN  FALSE
#define DEFAULT_CRC_REFOUT FALSE

static void
elf_riscv_before_parse (void)
{
  /* Default initialize the CRC parameters.  */
  riscv_crc_init   = DEFAULT_CRC_INIT;
  riscv_crc_poly   = DEFAULT_CRC_POLY;
  riscv_crc_xorout = DEFAULT_CRC_XOROUT;
  riscv_crc_refin  = DEFAULT_CRC_REFIN;
  riscv_crc_refout = DEFAULT_CRC_REFOUT;

  gld${EMULATION_NAME}_before_parse ();
}

static void
riscv_elf_before_allocation (void)
{
  gld${EMULATION_NAME}_before_allocation ();

  LANG_FOR_EACH_INPUT_STATEMENT(is)
  {
    asection *sec = is->the_bfd->sections;
    while (sec != NULL)
      {
	const char *secname = sec->name;
	const char *dstname = sec->output_section ? sec->output_section->name
	  : "";

	/* Produce an error if the input section name starts with ".ovlinput",
	 and the output name is not ".ovlgrps". Don't error if marked as exclude,
	 either by user, or gc-sections.  */
	if (strncmp (secname, ".ovlinput", strlen(".ovlinput")) == 0 &&
	    strcmp (dstname, ".ovlgrps") &&
	    !(sec->flags & SEC_EXCLUDE))
	  {
	    fprintf(stderr, "* '%s': '%s' -> '%s'\n", is->filename, secname,
	            dstname);
	    einfo(_("%F%P: Input section %s not correctly placed in"
	            ".ovlgrps\n"), secname);
	  }
	sec = sec->next;
      }
  }

  if (link_info.discard == discard_sec_merge)
    link_info.discard = discard_l;

  if (!bfd_link_relocatable (&link_info))
    {
      /* We always need at least some relaxation to handle code alignment.  */
      if (RELAXATION_DISABLED_BY_USER)
	TARGET_ENABLE_RELAXATION;
      else
	ENABLE_RELAXATION;
    }

  link_info.relax_pass = 3;
}

static void
gld${EMULATION_NAME}_after_allocation (void)
{
  int need_layout = 0;

  /* Don't attempt to discard unused .eh_frame sections until the final link,
     as we can't reliably tell if they're used until after relaxation.  */
  if (!bfd_link_relocatable (&link_info))
    {
      need_layout = bfd_elf_discard_info (link_info.output_bfd, &link_info);
      if (need_layout < 0)
	{
	  einfo (_("%X%P: .eh_frame/.stab edit: %E\n"));
	  return;
	}
    }

  ldelf_map_segments (need_layout);
}

/* This is a convenient point to tell BFD about target specific flags.
   After the output has been created, but before inputs are read.  */

static void
riscv_create_output_section_statements (void)
{
  /* See PR 22920 for an example of why this is necessary.  */
  if (strstr (bfd_get_target (link_info.output_bfd), "riscv") == NULL)
    {
      /* The RISC-V backend needs special fields in the output hash structure.
	 These will only be created if the output format is a RISC-V format,
	 hence we do not support linking and changing output formats at the
	 same time.  Use a link followed by objcopy to change output formats.  */
      einfo (_("%F%P: error: cannot change output format"
	       " whilst linking %s binaries\n"), "RISC-V");
      return;
    }
}

extern void
riscv_elf_overlay_hook_${EMULATION_NAME}(struct bfd_link_info *info);

extern void
riscv_elf_overlay_printmap_${EMULATION_NAME}(bfd *obfd,
                                             struct bfd_link_info *info,
                                             FILE *mapfile);

static void
riscv_elf_after_check_relocs (void)
{
  riscv_elf_overlay_hook_${EMULATION_NAME}(&link_info);
}

static const char * get_type_from_name_and_flags(const char *name, flagword flags, bfd_vma elftype) {
  if (flags & SEC_DEBUGGING)
    return "Debug Information";
  if (flags & SEC_CODE) {
    if (strcmp(name, ".ovlgrps") == 0)
      return "Overlay Group Data";
    return "Code";
  }
  if (flags & SEC_DATA) {
    if (elftype == SHT_INIT_ARRAY)
      return "Constructor Array";
    if (elftype == SHT_FINI_ARRAY)
      return "Destructor Array";
    if (strcmp(name, ".eh_frame") == 0)
      return "Exception Handling Frame Information";
    if (flags & SEC_READONLY)
      return "Read-only Data";
    return "Data";
  }
  if (elftype == SHT_NOBITS) {
    if (strcmp(name, ".bss") == 0)
      return "BSS";
    if (strcmp(name, ".stack") == 0)
      return "Stack";
    return "NOBITS";
  }
  if (elftype == 1879048195)
    return "RISC-V Attributes";
  if (elftype == SHT_PROGBITS)
    return "PROGBITS";
  return "Unknown";
}

static void
riscv_ovl_additional_link_map_text (bfd *obfd,
				    struct bfd_link_info *info ATTRIBUTE_UNUSED,
				    FILE *mapfile)
{
  if (mapfile == NULL)
    return;

  lang_memory_region_type *m;

  /* 1.1 Map file size summary  */
  minfo ("\nMemory summary\n\n");
  minfo ("MEMORY REGION                 MEMORY USED\n");
  minfo ("    SECTION                   SECTION SIZE       TYPE\n");
  for (m = get_lang_memory_region_list (); m != NULL; m = m->next)
    {
      char szbuf[100];
      bfd_vma memsize;
      lang_output_section_statement_type *s;

      /* Don't print the default memory region.  */
      if (strcmp (m->name_list.name, DEFAULT_MEMORY_REGION) == 0)
        continue;

      memsize = m->current - m->origin;
      float memsizef = memsize / 1024.0;
      char *suffix = "KiB";
      if (memsizef >= 1024.0)
        {
          memsizef /= 1024.0;
          suffix = "MiB";
        }
      if (memsizef >= 1024.0)
        {
          memsizef /= 1024.0;
          suffix = "GiB";
	}
      sprintf (szbuf, "%3.2f", memsizef);
      fprintf (config.map_file, "%-24s= %8li (%6s %s)\n", m->name_list.name,
               memsize, szbuf, suffix);

      s = &lang_os_list.head->output_section_statement;
      while (s != NULL)
        {
	  if (s->bfd_section != NULL && s->region == m)
            {
              asection *section = s->bfd_section;
              if (section->size > 0)
                {
                  float sectsizef = section->size / 1024.0;
                  sprintf (szbuf, "%3.2f", sectsizef);
                  fprintf (config.map_file, "    %-20s= %8li (%6s KiB)",
                           section->name, section->size, szbuf);
                  {
		    flagword flags = section->flags;
		    unsigned sec_shndx =
		      _bfd_elf_section_from_bfd_section (section->owner,
							 section);
		    Elf_Internal_Shdr *hdr =
		      elf_elfsections (section->owner)[sec_shndx];
		    fprintf (config.map_file, "  %s\n",
			     get_type_from_name_and_flags(section->name,
							  flags,
							  hdr->sh_type));
                  }
                }
            }
          s = s->next;
        }
    }

  /* 1.2 Map file sections summary.  */
  minfo ("\nSection summary\n\n");
  minfo ("NAME                  START    END        TYPE\n");
  {
    lang_output_section_statement_type *s;
    s = &lang_os_list.head->output_section_statement;
    while (s != NULL)
      {
	if (s->bfd_section != NULL && s->bfd_section->owner == obfd)
	  {
            asection *section = s->bfd_section;
            bfd_vma end = section->vma + section->size;
            flagword flags = section->flags;
            if (!(flags & SEC_EXCLUDE || flags & SEC_DEBUGGING))
	      {
		unsigned sec_shndx =
		  _bfd_elf_section_from_bfd_section (section->owner, section);
		Elf_Internal_Shdr *hdr =
		  elf_elfsections (section->owner)[sec_shndx];
		fprintf (config.map_file, "%-20s [%08lx-%08lx)",
			 section->name, section->vma, end);
		fprintf (config.map_file, "  %s\n",
			 get_type_from_name_and_flags(section->name, flags,
						      hdr->sh_type));
	      }
          }
	s = s->next;
      }
  }

  /* 1.3/1.4 Map file overlay sections.  */
  riscv_elf_overlay_printmap_${EMULATION_NAME}(link_info.output_bfd, &link_info,
					       config.map_file);
  minfo ("\n");
}

EOF

# Define some shell vars to insert bits of code into the standard elf
# parse_args and list_options functions.
#
PARSE_AND_LIST_PROLOGUE='
#define OPTION_GROUPING_FILE		301
#define OPTION_GROUPING_TOOL		302
#define OPTION_GROUPING_TOOL_ARGS	303
#define OPTION_FIRST_GROUP_NUMBER	304
#define OPTION_COMRV_DEBUG 		305
#define OPTION_COMRV_CRC_INIT		306
#define OPTION_COMRV_CRC_POLY		307
#define OPTION_COMRV_CRC_XOROUT		308
#define OPTION_COMRV_CRC_REFIN_ON	309
#define OPTION_COMRV_CRC_REFIN_OFF	310
#define OPTION_COMRV_CRC_REFOUT_ON	311
#define OPTION_COMRV_CRC_REFOUT_OFF	312
'

PARSE_AND_LIST_LONGOPTS='
  { "grouping-file",      required_argument, NULL, OPTION_GROUPING_FILE },
  { "grouping-tool",      required_argument, NULL, OPTION_GROUPING_TOOL },
  { "grouping-tool-args", required_argument, NULL, OPTION_GROUPING_TOOL_ARGS },
  { "first-group-number", required_argument, NULL, OPTION_FIRST_GROUP_NUMBER },
  { "comrv-debug",        no_argument,       NULL, OPTION_COMRV_DEBUG },
  { "comrv-crcinit",      required_argument, NULL, OPTION_COMRV_CRC_INIT },
  { "comrv-crcpolynomial",required_argument, NULL, OPTION_COMRV_CRC_POLY },
  { "comrv-crcxorout",    required_argument, NULL, OPTION_COMRV_CRC_XOROUT },
  { "comrv-crcrefin",     no_argument,       NULL, OPTION_COMRV_CRC_REFIN_ON },
  { "comrv-crcnorefin",   no_argument,       NULL, OPTION_COMRV_CRC_REFIN_OFF },
  { "comrv-crcrefout",    no_argument,       NULL, OPTION_COMRV_CRC_REFOUT_ON },
  { "comrv-crcnorefout",  no_argument,       NULL, OPTION_COMRV_CRC_REFOUT_OFF },
'

PARSE_AND_LIST_OPTIONS='
  fprintf (file, _("--grouping-file             Grouping file name\n"));
  fprintf (file, _("--grouping-tool             Name of the grouping tool command\n"));
  fprintf (file, _("--grouping-tool-args        Arguments to the grouping tool\n"));
  fprintf (file, _("--first-group-number        First group number for autogrouping\n"));
  fprintf (file, _("--comrv-crcinit             Initilization value used for CRCs\n"));
  fprintf (file, _("--comrv-crcpolynomial       Polynomial used for ComRV CRCs\n"));
  fprintf (file, _("--comrv-crcxorout           Final XOR value used for ComRV CRCs\n"));
  fprintf (file, _("--comrv-crcrefin            Enable input reflection for ComRV CRCs\n"));
  fprintf (file, _("--comrv-crcnorefin          Disable input reflection for ComRV CRCs\n"));
  fprintf (file, _("--comrv-crcrefout           Enable output reflection for ComRV CRCs\n"));
  fprintf (file, _("--comrv-crcnorefout         Disable output reflection for ComRV CRCs\n"));
'

PARSE_AND_LIST_ARGS_CASES='
    case OPTION_GROUPING_FILE:
      if (riscv_use_grouping_tool)
	einfo (_("--grouping-file provided, but --grouping-tools-args already "
	         "specified"), optarg);
      riscv_grouping_file = fopen (optarg, FOPEN_RT);
      if (riscv_grouping_file == NULL)
	einfo (_("%F%P: cannot open grouping file %s\n"), optarg);
      break;
    case OPTION_GROUPING_TOOL:
      if (riscv_grouping_file != NULL)
	einfo (_("--grouping-tool provided, but --grouping-file already "
	         "specified"), optarg);
      riscv_use_grouping_tool = TRUE;
      riscv_grouping_tool = malloc (strlen (optarg) + 1);
      strcpy (riscv_grouping_tool, optarg);
      riscv_grouping_tool[strlen (optarg)] = '\0';
      break;

    case OPTION_GROUPING_TOOL_ARGS:
      if (riscv_grouping_file != NULL)
	einfo (_("--grouping-tool-args provided, but --grouping-file already "
	         "specified"), optarg);
      riscv_use_grouping_tool = TRUE;
      riscv_grouping_tool_args = malloc (strlen (optarg) + 1);
      strcpy (riscv_grouping_tool_args, optarg);
      riscv_grouping_tool_args[strlen (optarg)] = '\0';
      break;
    case OPTION_FIRST_GROUP_NUMBER:
      {
	const char *end;
	riscv_ovl_first_group_number = bfd_scan_vma (optarg, &end, 0);
	if (*end != '\0' || riscv_ovl_first_group_number <= 0)
	  einfo (_("%P: warning: ignoring invalid --first-group-number value %s\n"),
	         optarg);
      }
      break;
    case OPTION_COMRV_DEBUG:
      riscv_comrv_debug = TRUE;
      break;
    case OPTION_COMRV_CRC_INIT:
      {
        const char *end;
        riscv_crc_init = bfd_scan_vma (optarg, &end, 0);
        if (*end != 0 || riscv_crc_init >= 0xffffffffU)
          {
            einfo (_("%P: warning: ignoring invalid ComRV CRC inital value %s\n"),
                   optarg);
            riscv_crc_init = DEFAULT_CRC_INIT;
          }
      }
      break;
    case OPTION_COMRV_CRC_POLY:
      {
        const char *end;
        riscv_crc_poly = bfd_scan_vma (optarg, &end, 0);
        if (*end != 0 || riscv_crc_poly >= 0xffffffffU)
          {
            einfo (_("%P: warning: ignoring invalid ComRV CRC polynomial %s\n"),
                   optarg);
            riscv_crc_poly = DEFAULT_CRC_POLY;
          }
      }
      break;
    case OPTION_COMRV_CRC_XOROUT:
      {
        const char *end;
        riscv_crc_xorout = bfd_scan_vma (optarg, &end, 0);
        if (*end != 0 || riscv_crc_xorout >= 0xffffffffU)
          {
            einfo (_("%P: warning: ignoring invalid ComRV CRC xorout %s\n"),
                   optarg);
            riscv_crc_xorout = DEFAULT_CRC_XOROUT;
          }
      }
      break;
    case OPTION_COMRV_CRC_REFIN_ON:
      riscv_crc_refin = TRUE;
      break;
    case OPTION_COMRV_CRC_REFIN_OFF:
      riscv_crc_refin = FALSE;
      break;
    case OPTION_COMRV_CRC_REFOUT_ON:
      riscv_crc_refout = TRUE;
      break;
    case OPTION_COMRV_CRC_REFOUT_OFF:
      riscv_crc_refout = FALSE;
      break;
'

LDEMUL_BEFORE_PARSE=elf_riscv_before_parse
LDEMUL_BEFORE_ALLOCATION=riscv_elf_before_allocation
LDEMUL_AFTER_ALLOCATION=gld${EMULATION_NAME}_after_allocation
LDEMUL_CREATE_OUTPUT_SECTION_STATEMENTS=riscv_create_output_section_statements
LDEMUL_AFTER_CHECK_RELOCS=riscv_elf_after_check_relocs
LDEMUL_EXTRA_EARLY_MAP_FILE_TEXT=riscv_ovl_additional_link_map_text
