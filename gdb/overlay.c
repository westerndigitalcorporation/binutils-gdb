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
  if (registered_overlay_manager != nullptr)
    {
      /* Remove all overlay event breakpoints.  The new overlay manager
	 might place them in a different location.  The overlay event
	 breakpoints will be created automatically for us the next time we
	 try to resume the inferior.  */
      delete_overlay_event_breakpoint ();
    }

  registered_overlay_manager = std::move (mgr);

  /* Discard all cached overlay state.  */

  /* Finally, ask the new overlay manager to read its internal state and
     populate our internal data structure.  */
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

std::vector<CORE_ADDR>
overlay_manager_get_mapped_addresses (CORE_ADDR addr)
{
  std::vector<CORE_ADDR> results;

  if (curr_mappings != nullptr)
    {
      for (const auto &m : *curr_mappings)
        {
          if (addr >= m.src && addr < (m.src + m.len))
            results.push_back (m.dst + (addr - m.src));
        }
    }

  return results;
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

      // This is the original logic.  This needs to be moved into a default
      // overlay manager class.
      // return (bl->section != nullptr && section_is_overlay (bl->section));
    }

  return false;

}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_non_overlay_address (CORE_ADDR addr)
{
  CORE_ADDR start, end;

  /* If ADDR is within a cache region then check the current mappings to
     see if one covers ADDR.  */
  if (registered_overlay_manager != nullptr
      && curr_mappings != nullptr
      && registered_overlay_manager->find_cache_region (addr, &start, &end))
    {
      /* Figure out what address this would have been before it was mapped
         in.  */
      for (const auto &m : *curr_mappings)
        {
          if (addr >= m.dst && addr < (m.dst + m.len))
            return m.src + (addr - m.dst);
        }
    }

  return addr;
}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_get_mapped_address_if_possible (CORE_ADDR addr)
{
  std::vector<CORE_ADDR> addrs
    = overlay_manager_get_mapped_addresses (addr);
  if (addrs.size () > 0)
    return addrs[0];
  return addr;
}

/* See overlay.h.  */

bool
overlay_manager_is_unmapped_overlay_address (CORE_ADDR addr)
{
  CORE_ADDR start, end;

  if (registered_overlay_manager != nullptr
      && registered_overlay_manager->find_storage_region (addr, &start, &end))
    return true;

  return false;
}

/* See overlay.h.  */

bool
overlay_manager_is_overlay_cache_address (CORE_ADDR addr)
{
  CORE_ADDR start, end;

  if (registered_overlay_manager != nullptr
      && registered_overlay_manager->find_cache_region (addr, &start, &end))
    return true;

  return false;
}

/* See overlay.h.  */

ULONGEST
overlay_manager_get_group_size (int group_id)
{
  if (registered_overlay_manager == nullptr)
    /* TODO: Should we throw an error here?  */
    return 0;

  return registered_overlay_manager->get_group_size (group_id);
}

/* See overlay.h.  */

CORE_ADDR
overlay_manager_get_group_unmapped_base_address (int group_id)
{
  if (registered_overlay_manager == nullptr)
    /* TODO: Should we throw an error here?  */
    return 0;

  return registered_overlay_manager->get_group_unmapped_base_address (group_id);
}

void _initialize_overlay (void);
void
_initialize_overlay (void)
{
}


