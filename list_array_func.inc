# Copyright (C) 2020 Greenbone Networks GmbH
# Some functions might have been moved from misc_func.inc into this
# include and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# @brief Converts a passed list to a new list containing only
#        items which are not duplicated within the original list.
#
# @param _FCT_ANON_ARGS One or more strings or lists to convert into a single list.
#
# @return A list containing only items which are not duplicated within the original list
#         or an empty list if no list was passed.
#
function make_list_unique() {

  local_var ret, args, _x, _z, _a, e, _r;

  ret = make_list();
  args = make_list();

  foreach _x( _FCT_ANON_ARGS ) {
    if( typeof( _x ) == "array" ) { # e.g. return value from http_cgi_dirs()
      foreach _z( _x )
        args = make_list( args, _z );
    } else {
      args = make_list( args, _x );
    }
  }

  foreach _a( args ) {

    e = FALSE;
    foreach _r( ret ) {
      if( _a == _r ) {
        e = TRUE; # entry already exist
        break;
      }
    }

    if( ! e )
      ret = make_list( ret, _a ); # entry didn't exist, add entry...
  }

  return ret;
}

function in_array( search, array, part_match, icase ) {

  local_var search, array, part_match, icase;
  local_var _val;

  if( typeof( array ) != "array" ) {
    set_kb_item( name:"vt_debug_no_array/" + get_script_oid(), value:get_script_oid() + "#-#array#-#in_array" );
    return;
  }

  if( ! search || isnull( search ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#search#-#in_array" );
    return;
  }

  # Default to case sensitive
  if( isnull( icase ) )
    icase = FALSE;

  if( icase )
    search = tolower( search );

  foreach _val( array ) {

    if( icase )
      _val = tolower( _val );

    if( part_match ) {
      if( search >< _val ) return TRUE;
    } else {
      if( _val == search ) return TRUE;
    }
  }
  return;
}

# @brief Checks if a specific array key exists in the passed array
#
# @param key        The key to check/evaluate.
# @param array      The array to check for the existence of the array key.
# @param part_match If set to TRUE (optional) a partial match/search for the
#                   array key is done.
# @param bin_search If binary data is included in the array to be searched the array
#                   key might hold a 0x00 raw_string. The foreach used in this function
#                   doesn't work for such a NULL char and thus this parameter needs to be
#                   set to TRUE (optional) so that the comparison works as expected.
# @param icase      If set to TRUE (optional) the comparison for the array key is done
#                   case insensitive. Defaults to FALSE (case sensitive). Only available /
#                   used if bin_search isn't set to TRUE.
#
# @return TRUE if the array key exists, FALSE otherwise and NULL if no array
#         was passed or the key parameter is missing.

function array_key_exist( key, array, part_match, bin_search, icase ) {

  local_var key, array, part_match, bin_search, icase;
  local_var _a;

  if( typeof( array ) != "array" ) {
    set_kb_item( name:"vt_debug_no_array/" + get_script_oid(), value:get_script_oid() + "#-#array#-#array_key_exist" );
    return NULL;
  }

  if( isnull( key ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#array_key_exist" );
    return NULL;
  }

  if( isnull( icase ) )
    icase = FALSE;

  if( icase )
    key = tolower( key );

  foreach _a( keys( array ) ) {

    if( bin_search ) {
      if( ! _a )
        _a = raw_string( 0x00 );
    } else {
      if( icase )
        _a = tolower( _a );
    }

    if( part_match ) {
      if( key >< _a )
        return TRUE;
    } else {
      if( _a == key )
        return TRUE;
    }
  }

  return;
}

function is_array() {

  local_var array, _a;

  array = _FCT_ANON_ARGS[0];

  if( ! array ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#is_array" );
    return;
  }

  if( typeof( array ) != "array" )
    return FALSE;

  if( max_index( array ) == 0 ) {
    foreach _a( array )
      return TRUE;

    return;
  }
  return TRUE;
}

function join( list, sep ) {

  local_var list, sep;
  local_var _l, ret;

  if( ! list ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#list#-#join" );
    return;
  }

  if( ! sep )
    sep = " ";

  foreach _l( list )
    ret += _l + sep;

  return ereg_replace( string:ret, pattern:sep + '$', replace:'' );
}

# @brief Converts a given list to an "or" regex like "(listitem1|listitem2)".
#
# @note If the list item is an empty string it won't be added to the pattern.
#
# @param list        The (mandatory) list to convert
# @param no_escaping If set to TRUE (default: FALSE) any char included in the list item which has a
#                    special meaning in regex will be escaped
#
# @return A string containing a regex pattern built from the given list or NULL if the list
#         parameter was empty, no list was given to it or if a list with a single item with an empty
#         string was given.
#
function list2or_regex( list, no_escaping ) {

  local_var list, no_escaping;
  local_var pattern, i, item;

  if( ! list ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#list#-#list2or_regex" );
    return;
  }

  if( typeof( list ) != "array" ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#list2or_regex: No list passed to the 'list' parameter." );
    return;
  }

  i = 0;

  foreach item( list ) {

    if( isnull( item ) || item == "" ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#list2or_regex: Ignoring empty list item." );
      continue;
    }

    if( ! no_escaping )
      item = ereg_replace( string:item, pattern:"(\*|\+|\?|\.|\||\{|\}|\^|\$)", replace:"\\1" ); # nb: We might want to move this into a separate function in the future...

    i++;

    if( i == 1 )
      pattern = "(" + item;
    else
      pattern += "|" + item;

  }

  # nb: e.g. if only an empty list was passed
  if( pattern )
    pattern += ")";
  else
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#list2or_regex: List with an single empty item given, not possible to create a regex from this." );

  return pattern;
}
