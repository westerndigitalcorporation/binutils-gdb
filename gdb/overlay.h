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
    ensure_region_data_loaded ();

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
    ensure_region_data_loaded ();

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

  /* HACK: Ideally this would not be needed in a final version of the
     overlay system, but right now I'm not sure how to fully move this code
     into Python.  Maybe it will become clear once everything is working.  */
  virtual bool has_multi_groups ()
  {
    return false;
  }

  /* HACK: Ideally this would not be needed in the final system, with all
     of this logic instead moved into Python code.

     If ADDR is with the region of a multi-groups first entry then a
     vector of all the alternative base addresses (within the storage
     region) for that multi-group, and update OFFSET to be the offset of
     ADDR from the start of the primary multi-group range.

     If ADDR is not within a multi-group then return an empty vector and
     OFFSET is not touched.

     TODO: This will not work for a multi-group containing a single group
     only.  Though this doesn't make much sense, I don't see why it
     shouldn't be valid, so we probably need a better API here.  */
  virtual std::vector<CORE_ADDR> find_multi_group (CORE_ADDR addr, CORE_ADDR *offset)
  {
    return {};
  }

  /* If ADDR is within any address range for any multi-group, then return
     a modified address within the matching multi-groups primary address
     range.

     If ADDR is not within any multi-group range then just return ADDR.  */
  virtual CORE_ADDR map_to_primary_multi_group_addr (CORE_ADDR addr)
  {
    return addr;
  }

  /* Unwind ComRV stack frame at SP, return previous stack pointer in
     PREV_SP, and the return address in RA.  If anything prevents unwinding
     then an error is thrown.  */
  virtual void unwind_comrv_stack_frame (CORE_ADDR sp, CORE_ADDR *prev_sp,
                                         CORE_ADDR *ra) = 0;

  /* Return the label within ComRV that indicates a function is returning
     through ComRV.  This will only be called once, the return value is
     cache within GDB.

     If ComRV is not active, then return 0 and GDB will not apply any
     special unwind filtering rules.  */
  virtual CORE_ADDR get_comrv_return_label (void) = 0;

protected:

  /* Overridden by subclasses to load region data.  */
  virtual void load_region_data (void) = 0;

private:
  /* When true GDB should reload the overlay manager state at the event
     breakpoint.  */
  bool m_reload_on_event;

  /* HACK: This is required to support the region tracking.  When that goes
     away, hopefully this will go away too.  */
  bool m_region_data_loaded = false;

  /* HACK: Should be removed eventually.  If the region data has not yet
     been loaded, then load it.  */
  void ensure_region_data_loaded (void)
  {
    if (!m_region_data_loaded)
      {
        load_region_data ();
        m_region_data_loaded = true;
      }
  }

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

/* If ADDR is in the overlay cache region then return the corresponding
   address from the overlay storage region.  When ADDR is a member of a
   multi-group and RESOLVE_MULTI_GROUP_P is false then the storage address
   return is for the precise multi-group member that was mapped in.
   However, when RESOLVE_MULTI_GROUP_P is true the storage address returned
   is instead for the multi-group member that has debug information
   available for it.  Remember, only one multi-group member will have
   debug, while all the others will not.

   If ADDR is not in the cache region then just return ADDR.  */

extern CORE_ADDR overlay_manager_cache_to_storage_address (CORE_ADDR addr,
                                                      bool resolve_multi_group_p = false);

/* If ADDR is a storage area address, and is currently mapped into the
   cache, then return the cache address, otherwise, return ADDR.  */

extern CORE_ADDR overlay_manager_get_cache_address_if_mapped (CORE_ADDR addr);

/* Return TRUE if there is any multi-groups in use.  */

extern bool overlay_manager_has_multi_groups ();

/* If ADDR is within the storage region address range of the primary
   function of a multi-group then return a list of all the alternative base
   addresses for that multi-group, and update OFFSET to indicate the
   offset of ADDR from the primary base address.

   Otherwise, return an empty list, and leave OFFSET unchanged.  */

extern std::vector<CORE_ADDR> overlay_manager_find_multi_group (CORE_ADDR addr, CORE_ADDR *offset);

/* Return true if ADDRESS is an address within the overlay storage region,
   otherwise, return false.

   If ADDRESS _is_ within the storage region, and if CACHE_ADDRESS is not
   NULL, then, if ADDRESS is currently mapped into the cache region, place
   the mapped address into CACHE_ADDRESS, otherwise, place ADDRESS into
   CACHE_ADDRESS.  */

extern bool overlay_manager_is_storage_address (CORE_ADDR address,
                                                CORE_ADDR *cache_address = nullptr);

/* Return true if ADDRESS is an address within the overlay cache region,
   otherwise, return false.

   If ADDRESS _is_ within the cache region, and if STORAGE_ADDRESS is not
   NULL, then, place the corresponding storage address into
   CACHE_ADDRESS.  */

extern bool overlay_manager_is_cache_address (CORE_ADDR address,
                                              CORE_ADDR *storage_address = nullptr,
                                              bool resolve_multi_group_p = false);

/* Called during stack unwinding to unwind an entry from the ComRV stack at
   COMRV_SP.  A return address within the overlay storage area is
   returned in RA, and the previous value of the ComRV stack pointer is
   returned in OLD_COMRV_SP.

   If anything goes wrong, or the stack can't be unwound then an error is
   thrown.  */

extern void overlay_manager_unwind_comrv_stack_frame (CORE_ADDR comrv_sp,
                                                      CORE_ADDR *old_comrv_sp,
                                                      CORE_ADDR *ra);

/* Return the magic address which indicates that a function return is going
   back through ComRV.  This will only be called once, and the return value
   will be cached.

   If the label is unknown, or ComRV is not in use, return 0, in which
   case the unwind code will not apply any special ComRV rules.  */

extern CORE_ADDR overlay_manager_get_comrv_return_label (void);

#endif /* !defined OVERLAY_H */
