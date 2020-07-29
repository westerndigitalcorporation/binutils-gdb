/* Copyright (C) 2019 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"

#include "gdbsupport/gdb_unique_ptr.h"
#include "symfile.h"
#include "overlay.h"
#include "gdbsupport/errors.h"

#include <cstdio>

/* The one registered overlay manager.  */

std::unique_ptr<gdb_overlay_manager> registered_overlay_manager = nullptr;

/* See overlay.h.  */

std::string
overlay_manager_event_symbol_name ()
{
  if (registered_overlay_manager != nullptr)
    return registered_overlay_manager->event_symbol_name ();

  /* The symbol name we return here is the historical default.  Maybe in
     the future this should return an empty string meaning no overlay
     debugging supported, and we should force all users to provide an
     overlay manager extension - and possibly GDB should ship with a
     default that closely matches the existing default behaviour.  */
  return "_ovly_debug_event";
}

/* See overlay.h.  */

void
overlay_manager_register (std::unique_ptr <gdb_overlay_manager> mgr)
{
  delete_overlay_event_breakpoint ();

  registered_overlay_manager = std::move (mgr);

  create_overlay_event_breakpoint ();
}

/* TODO: Global current mapping state, should this be stored in the overlay
   manager class maybe?  Also, I would like this to be a std::vector, not
   a std::unique_ptr to a std::vector, that seems wrong to me.  */
std::unique_ptr<std::vector<gdb_overlay_manager::mapping>> curr_mappings;

/* See overlay.h.  */

void
overlay_manager_hit_event_breakpoint (void)
{
  gdb_assert (registered_overlay_manager != nullptr);

  /* If the overlay manager doesn't want us to reload the overlay state
     when we hit the event breakpoint, then we're done.  */
  if (!registered_overlay_manager->reload_at_event_breakpoint ())
    return;

  std::unique_ptr<std::vector<gdb_overlay_manager::mapping>> mappings
    = registered_overlay_manager->read_mappings ();

  if (debug_overlay)
    {
      fprintf_unfiltered (gdb_stdlog,
                          "At overlay event breakpoint, read mappings:\n");
      if (mappings == nullptr)
        fprintf_unfiltered (gdb_stdlog, "\tNo mappings were returned\n");
      else
        {
          fprintf_unfiltered (gdb_stdlog, "\tGot %ld mappings:\n",
                              mappings->size ());
          for (const auto &m : (*mappings))
            fprintf_unfiltered (gdb_stdlog,
                                "\t\tFrom %s to %s (length %ld)\n",
                                core_addr_to_string (m.src),
                                core_addr_to_string (m.dst),
                                m.len);
        }
    }

  /* TODO: In the future we might want to compare the set of mappings we
     have now with the set of mappings we had previously so that we can
     figure out what has been mapped in, and what has just been mapped
     out.  This will, I think be required if we want to support always
     inserted breakpoints, as surely, this will be the point where
     breakpoints, even always inserted ones, will transition between
     actually being inserted and not.

     Anyway, for now, we don't support always inserted mode, so just store
     the current mapping state, and we can reference this later.  */
  curr_mappings = std::move (mappings);
}

/* See overlay.h.  */

bool
overlay_manager_is_overlay_breakpoint_loc (struct bp_location *bl)
{
  CORE_ADDR start, end;

  if (bl->loc_type == bp_loc_software_breakpoint
      || bl->loc_type == bp_loc_hardware_breakpoint)
    {
      /* Figure out if this is an overlay breakpoint.  For now this is done
         by assuming all breakpoints within either the overlay cache region,
         or the overlay storage region are overlay breakpoints.

         We need to check both addresses as breakpoints update their
         address as they are mapped in and out.

         TODO: It might be nice if we could somehow just mark the
         breakpoint categorically with a flag to indicate it is an overlay
         breakpoint, maybe even creating a different type of breakpoint
         would be awesome.  */
      if (registered_overlay_manager != nullptr
          && (registered_overlay_manager->find_storage_region (bl->address,
                                                               &start,
                                                               &end)
              || registered_overlay_manager->find_cache_region (bl->address,
                                                                &start,
                                                                &end)))
        return true;
    }

  return false;
}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_cache_to_storage_address (CORE_ADDR addr)
{
  CORE_ADDR storage_addr;

  if (!overlay_manager_is_cache_address (addr, &storage_addr, true))
    storage_addr = addr;
  if (debug_overlay > 9)
    fprintf_unfiltered (gdb_stdlog,
                        "overlay_manager_cache_to_storage_address "
                        "(%s) = %s\n", core_addr_to_string (addr),
                        core_addr_to_string (storage_addr));
  return storage_addr;
}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_get_cache_address_if_mapped (CORE_ADDR addr)
{
  CORE_ADDR cache_addr;

  if (!overlay_manager_is_storage_address (addr, &cache_addr))
    cache_addr = addr;
  else if (cache_addr == addr)
    {
      /* This is a storage area address, but we didn't immediately find a
         cache address for where this storage area address is mapped in.

         However, consider the case of the storage area being a multi-group
         address, in this case, there might be an alternative storage area
         address that is mapped in.  */
      CORE_ADDR tmp
        = registered_overlay_manager->map_to_primary_multi_group_addr (addr);
      CORE_ADDR offset;
      std::vector<CORE_ADDR> alt
        = registered_overlay_manager->find_multi_group (tmp, &offset);
      for (const CORE_ADDR &a : alt)
        {
          if (!overlay_manager_is_storage_address ((a + offset), &cache_addr))
            error (_("address was expected to be in the storage area"));
          if (cache_addr != (a + offset))
            break;
        }
    }

  return cache_addr;
}

/* See overlay.h.  */

bool
overlay_manager_has_multi_groups ()
{
  if (registered_overlay_manager == nullptr)
    return false;

  return registered_overlay_manager->has_multi_groups ();
}

/* See overlay.h.  */

std::vector<CORE_ADDR>
overlay_manager_find_multi_group (CORE_ADDR addr, CORE_ADDR *offset)
{
  if (registered_overlay_manager == nullptr)
    return {};

  return registered_overlay_manager->find_multi_group (addr, offset);
}

/* See overlay.h.  */

bool overlay_manager_is_storage_address (CORE_ADDR address,
                                         CORE_ADDR *cache_address)
{
  CORE_ADDR start, end;

  if (registered_overlay_manager != nullptr
      && registered_overlay_manager->find_storage_region (address, &start, &end))
    {
      if (cache_address != nullptr)
        {
          unsigned count = 0;

          if (curr_mappings != nullptr)
            {
              for (const auto &m : *curr_mappings)
                {
                  if (address >= m.src && address < (m.src + m.len))
                    {
                      ++count;
                      *cache_address = m.dst + (address - m.src);
                    }
                }
            }

          if (count == 0)
            *cache_address = address;
          else if (count > 1)
            error (_("storage address %s is mapped multiple times"),
                   core_addr_to_string (address));
        }

      return true;
    }

  return false;
}

/* See overlay.h.  */

bool overlay_manager_is_cache_address (CORE_ADDR address,
                                       CORE_ADDR *storage_address,
                                       bool resolve_multi_group_p)
{
  CORE_ADDR start, end;

  /* If ADDRESS is within a cache region then check the current mappings to
     see if one covers ADDRESS.  */
  if (registered_overlay_manager != nullptr
      && curr_mappings != nullptr
      && registered_overlay_manager->find_cache_region (address, &start, &end))
    {
      if (storage_address != nullptr)
        {
          unsigned count = 0;
          CORE_ADDR tmp;

          /* Figure out what address this would have been before it was
             mapped in.  */
          for (const auto &m : *curr_mappings)
            {
              if (address >= m.dst && address < (m.dst + m.len))
                {
                  ++count;
                  tmp = m.src + (address - m.dst);
                }
            }

          if (count > 1)
            error (_("multiple mappings for cache address %s"),
                   core_addr_to_string (address));
          else if (count == 1 && resolve_multi_group_p)
            tmp = registered_overlay_manager->map_to_primary_multi_group_addr (tmp);
          else if (count == 0)
            tmp = address;

          *storage_address = tmp;
        }

      return true;
    }

  return false;
}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_get_comrv_return_label (void)
{
  CORE_ADDR address = 0;

  if (registered_overlay_manager != nullptr)
    address = registered_overlay_manager->get_comrv_return_label ();
  return address;
}

/* Return the storage address for the callee that ComRV is about to call.  To
    be called when at comrv_invoke_callee.  */
static CORE_ADDR
overlay_manager_get_callee_unmapped_address ()
{
  CORE_ADDR addr;

  if (registered_overlay_manager == nullptr)
    /* TODO: Should we throw an error here?  */
    return 0;

  addr = registered_overlay_manager->get_callee_primary_storage_area_address ();

  return addr;
}

/* If func_name is a comrv entry point, find the address that will be hit
   immediately after exiting comrv, otherwise return 0.  */

CORE_ADDR
find_ovlmgr_resume_addr (struct gdbarch *gdbarch, struct frame_info *frame,
			 const char *func_name)
{
  CORE_ADDR addr;

  if (!strncmp ("comrvEntry", func_name, strlen (func_name))
      || !strncmp ("comrvEntry_context_switch", func_name, strlen (func_name)))
    addr = overlay_manager_get_callee_unmapped_address ();
  else if (!strncmp ("comrv_ret_from_callee", func_name, strlen (func_name))
	   || !strncmp ("comrv_ret_from_callee_context_switch", func_name,
			strlen (func_name)))
    addr = frame_unwind_caller_pc (frame);
  else
    return 0;

  if (debug_overlay)
    fprintf_unfiltered (gdb_stdlog,
                        "Stepped into overlay manager at %s\n", func_name);
  return addr;
}

struct frame_info *
find_ovlmgr_finish_frame (struct frame_info *frame) {
  const char *name;
  find_pc_partial_function (get_frame_pc (frame), &name, NULL, NULL);
  /* comrv_ret_from_callee is the only place in comrv that finish is expected to
     stop.  */
  if (!strncmp ("comrv_ret_from_callee", name, strlen (name)))
    /* Get the frame that comrv will return to.  */
    frame = frame_find_by_id (frame_unwind_caller_id (frame));

  return frame;
}

void _initialize_overlay (void);
void
_initialize_overlay (void)
{
}


