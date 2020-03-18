import gdb
import re

# Set this to True from within GDB to activate debug output from
# within this file.
overlay_debug = False

# Print STRING as a debug message if OVERLAY_DEBUG is True.
def debug (string):
    if not overlay_debug:
        return

    print (string)

# Required to make calls to super () work in python2.
__metaclass__ = type

INIT_SYMBOL = "g_stComrvCB.ucTablesLoaded"
OVERLAY_STORAGE_START_SYMBOL = "OVERLAY_START_OF_OVERLAYS"
OVERLAY_STORAGE_END_SYMBOL = "OVERLAY_END_OF_OVERLAYS"
OVERLAY_CACHE_START_SYMBOL = "__OVERLAY_CACHE_START__"
OVERLAY_CACHE_END_SYMBOL = "__OVERLAY_CACHE_END__"
OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES = 512

# The Overlay Cache Area is defined by a start and end label, this is
# the area into which code (and data?) is loaded in order to use it.
# This area is divided into "pages", each page is (currently) 512
# bytes (0x200) is size (see OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES)
# for this constant.
# The overlay tables are loaded into the last page of this cache
# area.
class overlay_data:
    _instance = None
    _mem_re = None

    # Holds information about all the groups and multi-groups.
    class _overlay_group_data:
        def __init__ (self, groups, multi_groups):
            self._groups = groups
            self._multi_groups = multi_groups

        def get_group (self, index):
            return self._groups[index]

    # Holds information about a single group.
    class _overlay_group:
        def __init__ (self, base_address, size_in_bytes):
            self._base_address = base_address
            self._size_in_bytes = size_in_bytes

        def base_address (self):
            return self._base_address

        def size_in_bytes (self):
            return self._size_in_bytes

    # A class to describe an area of memory.  This serves as a base
    # class for the cache region descriptor, and the storage region
    # descriptor classes.
    class _memory_region:
        # The START is the first address within the region, while END
        # is the first address just beyond the region.
        def __init__ (self, start, end):
            self._start_address = start
            self._end_address = end

        # Returns the first address within the region.
        def start_address (self):
            return self._start_address

        # Return the first address past the end of the region.
        def end_address (self):
            return self._end_address

    # A static description of the overlay cache area.  This is the
    # area of memory into which overlays are loaded so they can be
    # used.
    class _cache_descriptor (_memory_region):
        def __init__ (self, start, end):
            super (overlay_data._cache_descriptor, self).__init__ (start, end)

        # Return the address for the start of the cache region.
        def base_address (self):
            return self.start_address ()

        # Return the total size of the cache in bytes, including the tables
        # region.
        def size_in_bytes (self):
            return self.end_address () - self.start_address ()

        # Return the number of entries that are available for holding
        # overlays.  This excludes the area that is given up to hold the
        # overlay tables.  Currently the tables are copied into the last entry
        # in the cache.
        def number_of_working_entries (self):
            entry_size = self.entry_size_in_bytes ()
            return ((self.size_in_bytes () / entry_size)
                    - (self.tables_size_in_bytes () / entry_size))

        # Return the total number of entries that are in the cache, this
        # includes any entries being used to hold the overlay tables.
        def total_number_of_entries (self):
            entry_size = self.entry_size_in_bytes ()
            return (self.cache_size_in_bytes () / entry_size)

        # The address of the overlay tables within the cache.  Currently these
        # are always in the last entry of the cache, and are one entry in size.
        def tables_base_address (self):
            entry_size = self.entry_size_in_bytes ()
            return self.end_address () - self.tables_size_in_bytes ()

        # Return the size of the overlay tables region in bytes.  This is
        # currently always a single page of the cache.
        def tables_size_in_bytes (self):
            return self.entry_size_in_bytes ()

        # Return the size in bytes of a single entry (or page) within the
        # cache.
        def entry_size_in_bytes (self):
            return OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES

    # A class that describes the overlay systems storage area.  This
    # is the area of memory from which the overlays are loaded.  The
    # debug information will refer to this area,
    class _storage_descriptor (_memory_region):
        def __init__ (self, start, end):
            super (overlay_data._storage_descriptor, self).__init__ (start, end)

    # A wrapper class to hold all the different information we loaded from
    # target memory.  An instance of this is what we return from the fetch
    # method.
    class _overlay_data_inner:
        def __init__ (self, cache_descriptor, storage_descriptor, groups_data):
            self._cache_descriptor = cache_descriptor
            self._groups_data = groups_data
            self._storage_descriptor = storage_descriptor

        def cache (self):
            return self._cache_descriptor

        def storage (self):
            return self._storage_descriptor

        def group (self, index):
            return self._groups_data.get_group (index)

        def comrv_initialised (self):
            return (not self._groups_data == None)

    # Read the group offset for overlay group GROUP_NUMBER.  The
    # overlay data starts at address BASE_ADDRESS in memory.
    #
    # Return the offset in bytes for the specified overlay group.
    @staticmethod
    def _read_overlay_offset (base_address, end_address, group_number):
        base_address = base_address + (2 * group_number)
        if ((base_address + 1) >= end_address):
            raise RuntimeError ("out of bounds access while reading offset "
                                + "table for group %d" % (group_number))
        cmd = "x/1hx 0x%x" % (base_address)
        # TODO: Should be using the read_memory method on the inferior
        # here, but I can't get this to do anything useful.  Need to
        # figure this out, and at a minimum, improve the
        # documentation.
        output = gdb.execute (cmd, False, True)
        output = output.split ("\n")
        output = output[-2]
        if (overlay_data._mem_re == None):
            overlay_data._mem_re \
                = re.compile (r"0x[0-9a-f]+:\s+(0x[0-9a-f]+)")
        m = overlay_data._mem_re.match (output)
        if (m == None):
            raise RuntimeError ("failed to parse memory value from %s" % output)
        scaled_offset = int (m.group (1), 16)
        offset = OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES * scaled_offset
        return offset

    # Load information about all of the groups and multi-groups from the
    # overlay cache tables, and return an instance of an object holding all of
    # this data.
    @staticmethod
    def _load_group_data (table_start, table_size, storage_start):
        groups = list ()
        multi_groups = list ()

        # Read all of the overlay group offsets from memory, adding
        # entries to the overlay group list as we go.
        table_end = table_start + table_size
        prev_offset = 0
        grp = 0
        while (True):
            offset \
                = overlay_data._read_overlay_offset (table_start,
                                                            table_end,
                                                            grp)

            # An offset of 0 indicates the end of the group table, except for
            # the first entry of course, which represents the overlay tables,
            # and is always at offset 0.
            if (grp > 0 and offset == 0):
                break

            # Calculate the size of this overlay group, and create an
            # object to represent it.
            size = offset - prev_offset
            groups.append (overlay_data.
                           _overlay_group (storage_start + offset, size))
            grp += 1
            prev_offset = offset

        # This is where multi-group tokens should be loaded, but this
        # is not done yet.

        return (overlay_data.
                _overlay_group_data (groups, multi_groups))

    # Read the address of symbol NAME from the inferior, return the
    # address as an integer.
    @staticmethod
    def _read_symbol_address_as_integer (name):
        return int (gdb.parse_and_eval ("&%s" % (name)))

    # Read the value of symbol NAME from the inferior, return the
    # value as an integer.
    @staticmethod
    def _read_symbol_value_as_integer (name):
        return int (gdb.parse_and_eval ("%s" % (name)))

    # Load from target memory information about the overlay cache and the
    # overlay groups.
    @staticmethod
    def fetch ():
        if (overlay_data._instance != None):
            return overlay_data._instance

        # The overlay cache is defined by two symbols, a start and end
        # symbol.  Read these and create a cache descriptor object.
        cache_start = overlay_data.\
                      _read_symbol_address_as_integer \
				(OVERLAY_CACHE_START_SYMBOL)
        cache_end = overlay_data.\
                    _read_symbol_address_as_integer \
				(OVERLAY_CACHE_END_SYMBOL)
        cache_desc = overlay_data._cache_descriptor (cache_start, cache_end)

        # Similarly, the storage area, where overlays are loaded from, is
        # defined by a start and end symbol.
        storage_start = overlay_data.\
                        _read_symbol_address_as_integer \
				(OVERLAY_STORAGE_START_SYMBOL)
        storage_end = overlay_data.\
                        _read_symbol_address_as_integer \
				(OVERLAY_STORAGE_END_SYMBOL)
        storage_desc \
            = overlay_data._storage_descriptor (storage_start, storage_end)

        # Finally, if ComRV has been initialised then load the current state
        # from memory.
        init_been_called = overlay_data.\
                           _read_symbol_value_as_integer (INIT_SYMBOL)
        if (init_been_called):
            groups_data = overlay_data.\
                          _load_group_data (cache_desc.tables_base_address (),
                                            cache_desc.tables_size_in_bytes (),
                                            storage_start)
        else:
            groups_data = None

        # Now package all of the components into a single class
        # instance that we return.  We only cache the object if ComRV
        # has been initialised, in this way we shouldn't get stuck
        # with a cached, not initialised object.
        obj = overlay_data._overlay_data_inner (cache_desc, storage_desc,
                                                groups_data)
        if (init_been_called):
            overlay_data._instance = obj
        return obj

    # Discard the information loaded from the cache.  The next time fetch is
    # called the information will be reread.
    @staticmethod
    def clear ():
        overlay_data._instance = None

# Class for walking the overlay data structures and calling the
# visit_mapped_overlay method for every mapped overlay group.
class mapped_overlay_group_walker:
    # Call this to walk the overlay manager data structures in memory and
    # call the visit_mapped_overlay method for each mapped overlay group.
    def walk_mapped_overlays (self):
        # Grab the data that describes the current overlay state.
        ovly_data = overlay_data.fetch ()
        if (not ovly_data.comrv_initialised ()):
            self.comrv_not_initialised ()
            return

        # Now walk the overlay cache and see which entries are mapped in.
        index = 0
        while (index < ovly_data.cache ().number_of_working_entries ()):

            group = gdb.parse_and_eval ("g_stComrvCB.stOverlayCache[%d].unToken.stFields.uiOverlayGroupID" % (index))
            group = int (group)
            offset = None

            if (group != 0xffff):
                # Found an entry that is mapped in.

                group_desc = ovly_data.group (group)
                src_addr = group_desc.base_address ()
                length = group_desc.size_in_bytes ()
                dst_addr = (ovly_data.cache ().base_address ()
                            + (index
                               * ovly_data.cache ().entry_size_in_bytes ()))

                if (not self.visit_mapped_overlay (src_addr, dst_addr, length,
                                                index, group)):
                    break

                offset = gdb.parse_and_eval ("g_stComrvCB.stOverlayCache[%d].unProperties.stFields.ucSizeInMinGroupSizeUnits" % (index))
                offset = int (offset)
            else:
                # Found an entry that is not currently mapped.
                offset = 1

            # Move to the next cache entry.
            index += offset

    # Default implementation of visit_mapped_overlay, sub-classes should
    # override this method.  Return true to continue walking the list of
    # mapped overlays, or return false to stop.
    def visit_mapped_overlay (self, src_addr, dst_addr, length,
                              cache_index, group_number):
        return True

    # Default implementation of comrv_not_initialised, sub-classes
    # should override this method.
    def comrv_not_initialised (self):
        None

# The class represents a new GDB command 'parse-comrv' that reads the current
# overlay status and prints a summary to the screen.
class ParseComRV (gdb.Command):
    'Parse the ComRV data table.'

    def __init__ (self):
        gdb.Command.__init__ (self, "parse-comrv", gdb.COMMAND_NONE)

    def invoke (self, args, from_tty):

        # Class to walk the currently mapped overlays and print a summary.
        class print_mapped_overlays (mapped_overlay_group_walker):
            def __init__ (self):
                self.walk_mapped_overlays ()

            def visit_mapped_overlay (self, src_addr, dst_addr, length,
                                      cache_index, group_number):
                print ("Index %d is mapped to group %d"
                       % (cache_index, group_number))
                print ("  SRC: 0x%08x" % (src_addr))
                print ("  DST: 0x%08x" % (dst_addr))
                print ("  LEN: 0x%08x" % (length))
                return True

            def comrv_not_initialised (self):
                print ("ComRV not yet initialisd:")
                print ("      %s: %d"
                       % (INIT_SYMBOL,
                          int (gdb.parse_and_eval ("%s" % (INIT_SYMBOL)))))
                print ("     &%s: 0x%x"
                       % (INIT_SYMBOL,
                          int (gdb.parse_and_eval ("&%s" % (INIT_SYMBOL)))))

        print_mapped_overlays ()

        # Discard the cached cache data, incase we ran this command at the
        # wrong time and the cache information is invalid.  This will force
        # GDB to reload the information each time this command is run.
        overlay_data.clear ()

class MyOverlayManager (gdb.OverlayManager):
    def __init__ (self):
        gdb.OverlayManager.__init__ (self, True)
        ovly_data = overlay_data.fetch ()
        debug ("Setting up Overlay Manager:")
        debug ("Cache:")
        debug ("  Start: 0x%x" % (ovly_data.cache ().start_address ()))
        debug ("    End: 0x%x" % (ovly_data.cache ().end_address ()))
        debug ("Storage:")
        debug ("  Start: 0x%x" % (ovly_data.storage ().start_address ()))
        debug ("    End: 0x%x" % (ovly_data.storage ().end_address ()))
        self.set_storage_region (ovly_data.storage ().start_address (),
                                 ovly_data.storage ().end_address ())
        self.set_cache_region (ovly_data.cache ().start_address (),
                               ovly_data.cache ().end_address ())

    def __del__ (self):
        print ('Destructor called for MyOverlayManager')

    def event_symbol_name (self):
        debug ("In Python code, event_symbol_name")
        return "_ovly_debug_event"

    def read_mappings (self):
        debug ("In Python code, read_mappings")

        # Class to walk the currently mapped overlays and print a summary.
        class print_mapped_overlays (mapped_overlay_group_walker):
            def __init__ (self):
                self.walk_mapped_overlays ()

            def visit_mapped_overlay (self, src_addr, dst_addr, length,
                                      cache_index, group_number):
                debug ("Index %d is mapped to group %d"
                       % (cache_index, group_number))
                debug ("  SRC: 0x%08x" % (src_addr))
                debug ("  DST: 0x%08x" % (dst_addr))
                debug ("  LEN: 0x%08x" % (length))
                return True

        print_mapped_overlays ()

        # Class to walk mapped overlays and add them to the list of currently
        # mapped overlays.
        class map_overlays (mapped_overlay_group_walker):
            def __init__ (self, manager):
                self._manager = manager
                self.walk_mapped_overlays ()

            def visit_mapped_overlay (self, src_addr, dst_addr, length,
                                      cache_index, group_number):
                self._manager.add_mapping (src_addr, dst_addr, length)
                return True

        # Create an instance of the previous class, this does all the work in
        # its constructor.
        map_overlays (self)

        debug ("All mappings added")

        return True

    # This is a temporary hack needed to support backtracing.
    # Ideally, the whole backtracing stack unwind would move into
    # python, and then this function would not be needed, however, to
    # do that we will need some serious changes to how GDB's stack
    # unwinder works.
    #
    # For now then we need to expose a mechanism by which we can find
    # the size of a group given its group ID.
    def get_group_size (self, id):
        ovly_data = overlay_data.fetch ()
        if (not ovly_data.comrv_initialised ()):
            # Maybe we should through an error in this case?
            return 0

        group_desc = ovly_data.group (id)
        tmp = group_desc.size_in_bytes ()

        debug ("APB: Size of group %d is %d" % (id, tmp))
        return tmp

    # This is a temporary hack needed to support backtracing.
    # Ideally, the whole backtracing stack unwind would move into
    # python, and then this function would not be needed, however, to
    # do that we will need some serious changes to how GDB's stack
    # unwinder works.
    #
    # For now then we need to expose a mechanism by which we can find
    # the size of a group given its group ID.
    def get_group_unmapped_base_address (self, id):
        ovly_data = overlay_data.fetch ()
        if (not ovly_data.comrv_initialised ()):
            # Maybe we should through an error in this case?
            return 0

        group_desc = ovly_data.group (id)
        tmp = group_desc.base_address ()

        debug ("APB: Base address of group %d is 0x%x" % (id, tmp))
        return tmp

# Create an instance of the command class.
ParseComRV ()

# Create an instance of the overlay manager class.
MyOverlayManager ()

gdb.execute ("overlay auto", False, False)
gdb.execute ("set remote software-breakpoint-packet off", False, False)
