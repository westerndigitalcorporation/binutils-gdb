import gdb
import re

INIT_SYMBOL = "comrvInitHasBeenCalled"
OVERLAY_STORAGE_SYMBOL = "OVERLAY_START_OF_OVERLAYS"
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
class overlay_cache_data:
    __instance = None
    __mem_re = None

    class __overlay_group_data:
        def __init__ (self, groups, multi_groups):
            self.__groups = groups
            self.__multi_groups = multi_groups

        def get_group (self, index):
            return self.__groups[index]

    class __overlay_group:
        def __init__ (self, base_address, size_in_bytes):
            self.__base_address = base_address
            self.__size_in_bytes = size_in_bytes

        def base_address (self):
            return self.__base_address

        def size_in_bytes (self):
            return self.__size_in_bytes

    class __cache_descriptor:
        def __init__ (self, start, end):
            self.__start_address = start
            self.__end_address = end

        # Return the address for the start of the cache region.
        def cache_base_address (self):
            return self.__start_address

        # Return the total size of the cache in bytes, including the tables
        # region.
        def cache_size_in_bytes (self):
            return self.__end_address - self.__start_address

        # Return the number of entries that are available for holding
        # overlays.  This excludes the area that is given up to hold the
        # overlay tables.  Currently the tables are copied into the last entry
        # in the cache.
        def working_number_of_entries (self):
            entry_size = self.cache_entry_size_in_bytes ()
            return ((self.cache_size_in_bytes () / entry_size)
                    - (self.tables_size_in_bytes () / entry_size))

        # Return the total number of entries that are in the cache, this
        # includes any entries being used to hold the overlay tables.
        def total_number_of_entries (self):
            entry_size = self.cache_entry_size_in_bytes ()
            return (self.cache_size_in_bytes () / entry_size)

        # The address of the overlay tables within the cache.  Currently these
        # are always in the last entry of the cache, and are one entry in size.
        def tables_base_address (self):
            entry_size = self.cache_entry_size_in_bytes ()
            return self.__end_address - self.tables_size_in_bytes ()

        # Return the size of the overlay tables region in bytes.  This is
        # currently always a single page of the cache.
        def tables_size_in_bytes (self):
            return self.cache_entry_size_in_bytes ()

        # Return the size in bytes of a single entry (or page) within the
        # cache.
        def cache_entry_size_in_bytes (self):
            return OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES

    # A wrapper class to hold all the different information we loaded from
    # target memory.  An instance of this is what we return from the fetch
    # method.
    class __cache_data:
        def __init__ (self, cache_descriptor, groups_data):
            self.__cache_descriptor = cache_descriptor
            self.__groups_data = groups_data

        def working_number_of_entries (self):
            return self.__cache_descriptor.working_number_of_entries ()

        def cache_base_address (self):
            return self.__cache_descriptor.cache_base_address ()

        def get_group (self, index):
            return self.__groups_data.get_group (index)

        def cache_entry_size_in_bytes (self):
            return self.__cache_descriptor.cache_entry_size_in_bytes ()

    # Read the group offset for overlay group GROUP_NUMBER.  The
    # overlay data starts at address BASE_ADDRESS in memory.
    #
    # Return the offset in bytes for the specified overlay group.
    @staticmethod
    def __read_overlay_offset (base_address, end_address, group_number):
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
        if (overlay_cache_data.__mem_re == None):
            overlay_cache_data.__mem_re \
                = re.compile (r"0x[0-9a-f]+:\s+(0x[0-9a-f]+)")
        m = overlay_cache_data.__mem_re.match (output)
        if (m == None):
            raise RuntimeError ("failed to parse memory value from %s" % output)
        scaled_offset = int (m.group (1), 16)
        offset = OVERLAY_MIN_CACHE_ENTRY_SIZE_IN_BYTES * scaled_offset
        return offset

    # Load information about all of the groups and multi-groups from the
    # overlay cache tables, and return an instance of an object holding all of
    # this data.
    @staticmethod
    def __load_group_data (table_start, table_size, storage_start):
        groups = list ()
        multi_groups = list ()


        # Read all of the overlay group offsets from memory, adding
        # entries to the overlay group list as we go.
        table_end = table_start + table_size
        prev_offset = 0
        grp = 0
        while (True):
            offset \
                = overlay_cache_data.__read_overlay_offset (table_start,
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
            groups.append (overlay_cache_data.
                           __overlay_group (storage_start + offset, size))
            grp += 1
            prev_offset = offset

        # This is where multi-group tokens should be loaded, but this
        # is not done yet.

        return (overlay_cache_data.
                __overlay_group_data (groups, multi_groups))

    # Read the address of symbol NAME from the inferior, return the
    # address as an integer.
    @staticmethod
    def __read_symbol_address_as_integer (name):
        return int (gdb.parse_and_eval ("&%s" % (name)))

    # Read the value of symbol NAME from the inferior, return the
    # value as an integer.
    @staticmethod
    def __read_symbol_value_as_integer (name):
        return int (gdb.parse_and_eval ("%s" % (name)))

    # Load from target memory information about the overlay cache and the
    # overlay groups.
    @staticmethod
    def fetch ():
        if (overlay_cache_data.__instance != None):
            return overlay_cache_data.__instance

        # First we must check that ComRV has been initialised.
        init_been_called = overlay_cache_data.\
                           __read_symbol_value_as_integer (INIT_SYMBOL)
        if (not init_been_called):
            return None

        # The overlay cache is defined by two symbols, a start and end
        # symbol.  Read these and create a cache descriptor object.
        cache_start = overlay_cache_data.\
                      __read_symbol_address_as_integer \
                      		(OVERLAY_CACHE_START_SYMBOL)
        cache_end = overlay_cache_data.\
                    __read_symbol_address_as_integer \
                    		(OVERLAY_CACHE_END_SYMBOL)
        cache_desc = overlay_cache_data.__cache_descriptor (cache_start,
                                                            cache_end)

        # Now load the overlay group data from the tables within the cache.
        # In order to know where overlay groups are being loaded from we need
        # to find their storage base address.
        storage_start = overlay_cache_data.\
                        __read_symbol_address_as_integer \
                        	(OVERLAY_STORAGE_SYMBOL)
        groups_data = overlay_cache_data.\
                      __load_group_data (cache_desc.tables_base_address (),
                                         cache_desc.tables_size_in_bytes (),
                                         storage_start)

        # Now package all of the components into a single class instance that
        # we return.

        overlay_cache_data.__instance \
            = overlay_cache_data.__cache_data (cache_desc, groups_data)

        return overlay_cache_data.__instance

    # Discard the information loaded from the cache.  The next time fetch is
    # called the information will be reread.
    @staticmethod
    def clear ():
        overlay_cache_data.__instance = None

# Class for walking the overlay data structures and calling the
# visit_mapped_overlay method for every mapped overlay group.
class mapped_overlay_group_walker:
    # Call this to walk the overlay manager data structures in memory and
    # call the visit_mapped_overlay method for each mapped overlay group.
    def walk_mapped_overlays (self):
        # Grab the data that describes the static overlay state.  This data
        # is only loaded the first time these functions are called.
        cache_data = overlay_cache_data.fetch ()

        # If cache_data is None then this indicates that ComRV has not yet
        # been initialised.
        if (cache_data == None):
            self.comrv_not_initialised ()
            return

        # Now walk the overlay cache and see which entries are mapped in.
        index = 0
        while (index < cache_data.working_number_of_entries ()):

            group = gdb.parse_and_eval ("g_stComrvCB.stOverlayCache[%d].unToken.stFields.uiOverlayGroupID" % (index))
            group = int (group)
            offset = None

            if (group != 0xffff):
                # Found an entry that is mapped in.

                group_desc = cache_data.get_group (group)
                src_addr = group_desc.base_address ()
                length = group_desc.size_in_bytes ()
                dst_addr = (cache_data.cache_base_address ()
                            + (index
                               * cache_data.cache_entry_size_in_bytes ()))

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
                print ("ComRV not yet initialisd")

        print_mapped_overlays ()

        # Discard the cached cache data, incase we ran this command at the
        # wrong time and the cache information is invalid.  This will force
        # GDB to reload the information each time this command is run.
        overlay_cache_data.clear ()

class MyOverlayManager (gdb.OverlayManager):
    def __init__ (self):
        gdb.OverlayManager.__init__ (self, True)

    def __del__ (self):
        print ('Destructor called for MyOverlayManager')

    def event_symbol_name (self):
        print "In Python code, event_symbol_name"
        return "_ovly_debug_event"

    def read_mappings (self):
        print "In Python code, read_mappings"

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

        print_mapped_overlays ()

        # Class to walk mapped overlays and add them to the list of currently
        # mapped overlays.
        class map_overlays (mapped_overlay_group_walker):
            def __init__ (self, manager):
                self.__manager = manager
                self.walk_mapped_overlays ()

            def visit_mapped_overlay (self, src_addr, dst_addr, length,
                                      cache_index, group_number):
                super (MyOverlayManager, self.__manager).\
                    add_mapping (src_addr, dst_addr, length)
                return True

        # Create an instance of the previous class, this does all the work in
        # its constructor.
        map_overlays (self)

        print "All mappings added"

        return True

# Create an instance of the command class.
ParseComRV ()

# Create an instance of the overlay manager class.
MyOverlayManager ()

gdb.execute ("overlay auto", False, False)
gdb.execute ("set remote software-breakpoint-packet off", False, False)
