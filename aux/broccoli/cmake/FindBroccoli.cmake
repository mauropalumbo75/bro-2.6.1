# - Try to find libbroccoli include dirs and libraries 
#
# Usage of this module as follows:
#
#     find_package(Broccoli)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  Broccoli_ROOT_DIR         Set this variable to the root installation of
#                            libbroccoli if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  BROCCOLI_FOUND            System has libbroccoli, include and lib dirs found
#  Broccoli_INCLUDE_DIR      The libbroccoli include directories. 
#  Broccoli_LIBRARY          The libbroccoli library.

find_path(Broccoli_ROOT_DIR
    NAMES include/broccoli.h
)

find_path(Broccoli_INCLUDE_DIR
    NAMES broccoli.h
    HINTS ${Broccoli_ROOT_DIR}/include
)

find_library(Broccoli_LIBRARY
    NAMES broccoli
    HINTS ${Broccoli_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Broccoli DEFAULT_MSG
    Broccoli_LIBRARY
    Broccoli_INCLUDE_DIR
)

mark_as_advanced(
    Broccoli_ROOT_DIR
    Broccoli_INCLUDE_DIR
    Broccoli_LIBRARY
)
