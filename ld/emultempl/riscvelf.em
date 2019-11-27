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

static void
riscv_elf_before_allocation (void)
{
  fprintf(stderr, "* riscv_elf_before_allocation\n");
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
         and the output name is not ".ovlallfns".  */
	if (strncmp (secname, ".ovlinput", strlen(".ovlinput")) == 0 &&
	    strcmp (dstname, ".ovlallfns"))
          {
	    fprintf(stderr, "* '%s': '%s' -> '%s'\n", is->filename, secname,
		    dstname);
            //einfo(_("%F%P: Input section %s not correctly placed in"
		    //".ovlallfns\n"), secname);
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

static void
riscv_elf_after_check_relocs (void)
{
  riscv_elf_overlay_hook_${EMULATION_NAME}(&link_info);
}

EOF

# Define some shell vars to insert bits of code into the standard elf
# parse_args and list_options functions.
#
PARSE_AND_LIST_PROLOGUE='
#define OPTION_GROUPING_FILE		301
#define OPTION_GROUPING_TOOL_ARGS	302
'

PARSE_AND_LIST_LONGOPTS='
  { "grouping-file",      required_argument, NULL, OPTION_GROUPING_FILE },
  { "grouping-tool-args", required_argument, NULL, OPTION_GROUPING_TOOL_ARGS },
'

PARSE_AND_LIST_OPTIONS='
  fprintf (file, _("--grouping-file             Grouping file name\n"));
  fprintf (file, _("--grouping-tool-args        Arguments to the grouping tool\n"));
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
    case OPTION_GROUPING_TOOL_ARGS:
      if (riscv_grouping_file != NULL)
	einfo (_("--grouping-tool-args provided, but --grouping-file already "
	         "specified"), optarg);
      riscv_use_grouping_tool = TRUE;
      riscv_grouping_tool_args = malloc (strlen (optarg) + 1);
      strcpy(riscv_grouping_tool_args, optarg);
      riscv_grouping_tool_args[strlen (optarg)] = '\0';
      break;
'

LDEMUL_BEFORE_ALLOCATION=riscv_elf_before_allocation
LDEMUL_AFTER_ALLOCATION=gld${EMULATION_NAME}_after_allocation
LDEMUL_CREATE_OUTPUT_SECTION_STATEMENTS=riscv_create_output_section_statements
LDEMUL_AFTER_CHECK_RELOCS=riscv_elf_after_check_relocs
