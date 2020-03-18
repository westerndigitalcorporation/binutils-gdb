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

/* Data structures and function declarations to aid GDB in managing
   overlays.  */

#if !defined (OVERLAY_H)
#define OVERLAY_H 1

#include "breakpoint.h"

#include <string>
#include <memory>

extern unsigned int debug_overlay;

class gdb_overlay_manager
{
public:

  /* Constructor.  */
  gdb_overlay_manager (bool reload_on_event)
    : m_reload_on_event (reload_on_event)
  { /* Nothing.  */ }

  /* Destructor.  */
  virtual ~gdb_overlay_manager ()
  { /* Nothing.  */ }

  /* Return the name of the symbol at which GDB should place a breakpoint
     in order to detect changes in the overlay manager state.  Return the
     empty string if no breakpoint should be placed.  */
  virtual std::string event_symbol_name () const = 0;

  /* Return true if GDB should reload the overlay manager state at the
     event breakpoint in order to detect changes in the state.  */
  bool reload_at_event_breakpoint () const
  {
    return m_reload_on_event;
  }

  /* Represents a mapped in region.   */
  struct mapping
  {
    mapping (CORE_ADDR s, CORE_ADDR d, size_t l)
      : src (s), dst (d), len (l)
    { /* Nothing.  */ }

    /* The address from which the region is loaded.  */
    CORE_ADDR src;

    /* The address to which the region has been loaded.  */
    CORE_ADDR dst;

    /* The length (in bytes) of the region.  */
    size_t len;
  };

  virtual std::unique_ptr<std::vector<mapping>> read_mappings () = 0;

  /* Set the cache regions list from REGIONS.  See the comment on
     M_CACHE_REGIONS, this method probably shouldn't be in this class.  */
  void set_cache_regions (std::vector<std::pair<CORE_ADDR, CORE_ADDR>> regions)
  {
    m_cache_regions = regions;
  }

  /* Set the storage regions list from REGIONS.  See the comment on
     M_STORAGE_REGIONS, this method probably shouldn't be in this class.  */
  void set_storage_regions (std::vector<std::pair<CORE_ADDR, CORE_ADDR>> regions)
  {
    m_storage_regions = regions;
  }

  /* If ADDR is within a cache region then update START and END to the
     extents of the cache region and return true, otherwise the contents
     of START and END are untouched and return false.  */
  bool find_cache_region (CORE_ADDR addr, CORE_ADDR *start, CORE_ADDR *end)
  {
    for (const auto &r : m_cache_regions)
      {
        if (r.first <= addr && r.second > addr)
          {
            *start = r.first;
            *end = r.second;
            return true;
          }
      }

    return false;
  }

  /* If ADDR is within a storage region then update START and END to the
     extents of the cache region and return true, otherwise the contents
     of START and END are untouched and return false.  */
  bool find_storage_region (CORE_ADDR addr, CORE_ADDR *start, CORE_ADDR *end)
  {
    for (const auto &r : m_storage_regions)
      {
        if (r.first <= addr && r.second > addr)
          {
            *start = r.first;
            *end = r.second;
            return true;
          }
      }

    return false;
  }

  /* HACK: This is only needed until we can move the stack unwinding into
     the Python overlay manager.  Return the size of group GROUP_ID in
     bytes.  */
  virtual ULONGEST get_group_size (int group_id)
  {
    /* TODO: Should this be an error?  */
    return 0;
  }

  /* HACK: Return the unmapped base address for group GROUP_ID.  */
  virtual CORE_ADDR get_group_unmapped_base_address (int group_id)
  {
    /* TODO: Should this be an error?  */
    return 0;
  }

private:
  /* When true GDB should reload the overlay manager state at the event
     breakpoint.  */
  bool m_reload_on_event;

  /* The lists of cache and storage regions.  Each is a list of pairs, with
     each pair being a start and end address.

     TODO: These need to be moved into a sub-class, as only some types of
     overlay manager will actually need these fields.  */
  std::vector<std::pair<CORE_ADDR, CORE_ADDR>> m_cache_regions;
  std::vector<std::pair<CORE_ADDR, CORE_ADDR>> m_storage_regions;
};

/* Return a string containing the name of a symbol at which we should stop
   in order to read in the current overlay state.  This symbol will be
   reached every time the overlay manager state changes.  */

extern std::string overlay_manager_event_symbol_name ();

/* Register an overlay manager.  The can only be one overlay manager in use
   at a time, if a manager is already registered then this will throw an
   error.  */

extern void overlay_manager_register
	(std::unique_ptr <gdb_overlay_manager> mgr);

/* Call this when the inferior hits the overlay event breakpoint.  Ensure
   that GDB has claimed the terminal before this is called.  At the moment
   this assumes that the current inferior/thread is the one that hit the
   event breakpoint, don't know if this is a good assumption, or if we
   should pass in the thread in which the breakpoint was hit.  */

extern void overlay_manager_hit_event_breakpoint (void);

/* Return true if breakpoint location BL is an overlay breakpoint
   location.  */

extern bool overlay_manager_is_overlay_breakpoint_loc (struct bp_location *bl);

/* Return a vector of the addresses to which ADDR is currently mapped.
   The returned vector could have 0 or more entries (including more than
   1 if ADDR is mapped in multiple times).  */

extern std::vector<CORE_ADDR> overlay_manager_get_mapped_addresses (CORE_ADDR addr);

/* If ADDR is an address that was mapped in from an overlay source region,
   then return the corresponding address in the overlay source region,
   otherwise, return ADDR.  */

extern CORE_ADDR overlay_manager_non_overlay_address (CORE_ADDR addr);

/* If ADDR is currently mapped in, then return the first mapped address,
   otherwise return ADDR.  */

extern CORE_ADDR overlay_manager_get_mapped_address_if_possible (CORE_ADDR addr);

/* Return true if ADDR is an address that could be mapped in.  */

extern bool overlay_manager_is_unmapped_overlay_address (CORE_ADDR addr);

/* Return true if ADDR is within the cache region.  */

extern bool overlay_manager_is_overlay_cache_address (CORE_ADDR addr);

/* Return the size (in bytes) of overlay group GROUP_ID.  */

extern ULONGEST overlay_manager_get_group_size (int group_id);

/* Return the unmapped base address of overlay group GROUP_ID.  */

extern CORE_ADDR overlay_manager_get_group_unmapped_base_address (int group_id);

#endif /* !defined OVERLAY_H */
