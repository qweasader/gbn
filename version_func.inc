# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# XXX: the version tests should be eventually consolidated with
# the methods from revisions-lib.inc.

# @brief Checks if the given version passed via the 'version' parameter is less than the version
#        given via the 'test_version' parameter.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is less than the version passed via
#         the 'test_version' parameter, FALSE otherwise.
#
function version_is_less( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_less" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_less" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_less: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_less: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  return( version_test( version:version, test_version:test_version, less:TRUE, icase:icase, debug:debug ) );
}

# @brief Checks if the given version passed via the 'version' parameter is equal to the version
#        given via the 'test_version' parameter.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is equal to the version passed via
#         the 'test_version' parameter, FALSE otherwise.
function version_is_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_equal" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_equal" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  return( version_test( version:version, test_version:test_version, less:FALSE, icase:icase, debug:debug ) );
}

# @brief Checks if the given version passed via the 'version' parameter is less or equal to the
#        version given via the 'test_version' parameter.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is less or equal to the version
#         passed via the 'test_version' parameter, FALSE otherwise.
function version_is_less_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_less_equal" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_less_equal" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_less_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_less_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  if( version_is_equal( version:version, test_version:test_version, icase:icase, debug:debug ) )
    return TRUE;

  if( version_is_less( version:version, test_version:test_version, icase:icase, debug:debug ) )
    return TRUE;

  return FALSE;
}

# @brief Checks if the given version passed via the 'version' parameter is greater or equal to the
#        version given via the 'test_version' parameter.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is greater or equal to the version
#         passed via the 'test_version' parameter, FALSE otherwise.
function version_is_greater_equal( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_greater_equal" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_greater_equal" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_greater_equal: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_greater_equal: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  if( version_is_equal( version:version, test_version:test_version, icase:icase, debug:debug ) )
    return TRUE;

  if( version_is_less( version:test_version, test_version:version, icase:icase, debug:debug ) )
    return TRUE;

  return FALSE;
}

# @brief Checks if the given version passed via the 'version' parameter is greater than the version
#        given via the 'test_version' parameter.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is greater than the version passed
#         via the 'test_version' parameter, FALSE otherwise.
#
function version_is_greater( version, test_version, icase, debug ) {

  local_var version, test_version, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_is_greater" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_is_greater" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_greater: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_is_greater: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  if( version_is_less( version:test_version, test_version:version, icase:icase, debug:debug ) )
    return TRUE;

  return FALSE;
}

# @brief Checks if the given version passed via the 'version' parameter is in the range of the
#        versions given via the 'test_version' (lower version) and 'test_version2' parameters
#        (upper version).
#
# @note This function works 'inclusive', means that both versions passed via the 'test_version' and
#       'test_version2' parameters are included when determining if the passed version (via the
#       'version' parameter) is included within the tested range.
#
# @param version       The version to be tested.
# @param test_version  The "lower" version to be tested against.
# @param test_version2 The "upper" version to be tested against.
# @param icase         TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug         If set to TRUE additional debug logging about the version comparison is done
#                      on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is in the range of the versions
#         given via the 'test_version' (lower version) and 'test_version2' parameters
#         (upper version), FALSE otherwise.
#
function version_in_range( version, test_version, test_version2, icase, debug ) {

  local_var version, test_version, test_version2, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_in_range" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#version_in_range" );

  if( ! test_version2 )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version2#-#version_in_range" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version =~ "^\s+" || test_version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'test_version' parameter which might show an unexpected behavior." );

  if( test_version2 =~ "^\s+" || test_version2 =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range: Trailing / leading space passed to 'test_version2' parameter which might show an unexpected behavior." );

  if( version_is_greater_equal( version:version, test_version:test_version, icase:icase, debug:debug ) ) {
    if( version_is_less_equal( version:version, test_version:test_version2, icase:icase, debug:debug ) )
      return TRUE;
  }
  return FALSE;
}

# @brief Checks if the given version passed via the 'version' parameter is in the range of the
#        versions given via the 'test_version_lo' (lower version) and 'test_version_up' parameters
#        (upper version).
#
# @note This function works 'exclusive' by default for the version passed via the 'test_version_up'
#       parameter, means that it is excluded when determining if the passed version (via the
#       'version' parameter) is included within the tested range. This default was chosen because
#       most common vendor advisories are giving a starting range of affected versions as the lowest
#       version and the first fixed version.
#
# @param version         The version to be tested.
# @param test_version_lo The "lower" version to be tested against.
# @param test_version_up The "upper" version to be tested against.
# @param lower_exclusive If set to TRUE (default is FALSE) the version passed via the
#                        'test_version_lo' parameter is excluded when determining if the passed
#                        version (via the 'version' parameter) is included within the tested range.
# @param upper_exclusive If set to TRUE (default is TRUE) the version passed via the
#                        'test_version_up' parameter is excluded when determining if the passed
#                        version (via the 'version' parameter) is included within the tested range.
# @param icase           TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug           If set to TRUE additional debug logging about the version comparison is done
#                        on the command line.
#
# @return TRUE if the version passed via the 'version' parameter is in the range of the versions
#         given via the 'test_version_lo' (lower version, inclusive by default) and
#         'test_version_up' parameters (upper version, exclusive by default), FALSE otherwise.
#
function version_in_range_exclusive( version, test_version_lo, test_version_up, lower_exclusive, upper_exclusive, icase, debug ) {

  local_var version, test_version_lo, test_version_up, lower_exclusive, upper_exclusive, icase, debug;

  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#version_in_range_exclusive" );

  if( ! test_version_lo )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version_lo#-#version_in_range_exclusive" );

  if( ! test_version_up )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version_up#-#version_in_range_exclusive" );

  if( version =~ "^\s+" || version =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range_exclusive: Trailing / leading space passed to 'version' parameter which might show an unexpected behavior." );

  if( test_version_lo =~ "^\s+" || test_version_lo =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range_exclusive: Trailing / leading space passed to 'test_version_lo' parameter which might show an unexpected behavior." );

  if( test_version_up =~ "^\s+" || test_version_up =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#version_in_range_exclusive: Trailing / leading space passed to 'test_version_up' parameter which might show an unexpected behavior." );

  # nb: Set some defaults according to the function description.
  if( isnull( lower_exclusive ) )
    lower_exclusive = FALSE;

  if( isnull( upper_exclusive ) )
    upper_exclusive = TRUE;

  if( lower_exclusive && upper_exclusive ) {
    if( version_is_greater( version:version, test_version:test_version_lo, icase:icase, debug:debug ) ) {
      if( version_is_less( version:version, test_version:test_version_up, icase:icase, debug:debug ) )
        return TRUE;
    }
  }

  else if( lower_exclusive ) {
    if( version_is_greater( version:version, test_version:test_version_lo, icase:icase, debug:debug ) ) {
      if( version_is_less_equal( version:version, test_version:test_version_up, icase:icase, debug:debug ) )
        return TRUE;
    }
  }

  else if( upper_exclusive ) {
    if( version_is_greater_equal( version:version, test_version:test_version_lo, icase:icase, debug:debug ) ) {
      if( version_is_less( version:version, test_version:test_version_up, icase:icase, debug:debug ) )
        return TRUE;
    }
  }

  # nb: Basically what version_in_range() is doing.
  else {
    if( version_is_greater_equal( version:version, test_version:test_version_lo, icase:icase, debug:debug ) ) {
      if( version_is_less_equal( version:version, test_version:test_version_up, icase:icase, debug:debug ) )
        return TRUE;
    }
  }

  return FALSE;
}

# @brief Creates a report containing e.g. installed and fixed versions based on the given data.
#
# @param installed_version The installed version found on the target.
# @param installed_build   The installed build found on the target.
# @param installed_patch   The installed patch found on the target.
# @param vulnerable_range  The vulnerable version range which was used in the version test.
# @param file_checked      The vulnerable file which was checked / used in the version test.
# @param file_version      The vulnerable file version which was used in the version test.
# @param reg_checked       The Windows registry key which was used in the version test.
# @param fixed_version     The version which includes a known fix.
# @param fixed_build       The build which includes a known fix.
# @param fixed_patch       The patch which includes a known fix.
# @param extra             An extra string (in free form) to be added at the end of the report.
# @param install_path      The installation path / port on which the installed product was found on
#                          the target.
# @param install_url       The installation URL on which the installed product was found on the
#                          target.
#
# @return A report (as a string) based on the given data.
#
function report_fixed_ver( installed_version, installed_build, installed_patch, vulnerable_range, file_checked, file_version, reg_checked, fixed_version, fixed_build, fixed_patch, extra, install_path, install_url ) {

  local_var installed_version, installed_build, installed_patch, vulnerable_range, file_checked, file_version;
  local_var reg_checked, fixed_version, fixed_build, fixed_patch, extra, install_path, install_url;
  local_var report;

  if( ! installed_version && ! file_checked ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#installed_version/file_checked#-#report_fixed_ver" );
  if( ! fixed_version && ! vulnerable_range ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fixed_version/vulnerable_range#-#report_fixed_ver" );

  if( installed_version ) report += 'Installed version: ' + installed_version + '\n';
  if( installed_build )   report += 'Installed build:   ' + installed_build + '\n';
  if( installed_patch )   report += 'Installed patch:   ' + installed_patch + '\n';
  if( fixed_version )     report += 'Fixed version:     ' + fixed_version + '\n';
  if( fixed_build )       report += 'Fixed build:       ' + fixed_build + '\n';
  if( fixed_patch )       report += 'Fixed patch:       ' + fixed_patch + '\n';
  if( vulnerable_range )  report += 'Vulnerable range:  ' + vulnerable_range + '\n';

  if( file_checked )      report += 'File checked:      ' + file_checked + '\n';
  if( file_version )      report += 'File version:      ' + file_version + '\n';
  if( reg_checked )       report += 'Reg-Key checked:   ' + reg_checked + '\n';

  if( install_path ) {
                          report += 'Installation\n';
                          report += 'path / port:       ' + install_path + '\n';
  }
  if( install_url )       report += 'Installation URL:  ' + install_url + '\n';
  if( extra )             report += '\n' + extra + '\n';

  return report;
}

# @brief Internal function for version comparison, not to be called directly. Please use the
#        "wrapper" functions like @ref version_is_less instead.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
# @param less         TRUE if the function should check if the version is less than (<), FALSE otherwise
#                     (default)
# @param icase        TRUE (the default) if the check should be case insensitive, FALSE if otherwise.
# @param debug        If set to TRUE additional debug logging about the version comparison is done
#                     on the command line.
#
# @todo Implement 1.0.0a > 1.0.0alpha/beta/rc
#
# @return Returns TRUE if the version comparison matched the desired check, FALSE otherwise
#
function version_test( version, test_version, less, icase, debug ) {

  local_var version, test_version, less, icase, debug;
  local_var ver_sep, ver_ary, test_ary, _i, r, s, test_prerelease, char_found, ver_prerelease;

  if( isnull( version ) || version == "" || version == 0 || version == '0' || version == "unknown" || version == "Unknown" || version == "." )
    return FALSE;

  if( isnull( icase ) )
    icase = TRUE;

  if( icase ) {
    version = tolower( version );
    test_version = tolower( test_version );
  }

  if( debug ) display( 'DEBUG: Initial version: ' + version + ' and test_version: ' + test_version );

  # set / use a standard separator for the version and test_version parameter
  ver_sep = "."; # Set Standard Separator

  # Replace commonly used version separators (e.g. 1.0 rc1, or 1.0-rc1) with the standard separator.
  # nb: The "\.\." replacement is a fallback for VTs passing doubled dots to the version comparison functions.
  # Such a doubled point would e.g. report "1.0..99" to be a lower version then 1.0.1
  # For Java VTs updated regex, 'update_' to be replaced by '.'. 1.8.0_151 , 1.8.0update_51, 1.7.0update1
  # Replace as well brackets in the version like seen in Cisco products, e.g. '9.8(4)41'
  version = ereg_replace( pattern:"( |\-|\.\.|_|update_|\(|\))", string:version, replace:"." );
  # nb: Also make sure that we don't have any trailing dots (like "9.8.41.4." from e.g. the ()
  # replacement above).
  version = ereg_replace( pattern:"\.$", string:version, replace:"" );

  # Next few lines for Java only
  # For case 1.7.0update1 --> 1.7.0.update.1
  if( version =~ "[0-9]update[0-9]" )
    version = ereg_replace( pattern:"update", string:version, replace:".update." );

  # Few Java VTs are doing this, removing e.g. '-b11'
  version = ereg_replace( pattern:"-b[0-9][0-9]", string:version, replace:"" );

  test_version = ereg_replace( pattern:"( |\-|\.\.|_)", string:test_version, replace:"." );

  if( debug ) display( 'DEBUG: version: ' + version + ' and test_version: ' + test_version + ' after applying standard separator' );

  # Some versions have e.g. 1.0.0g or 1.0.0beta1 so add a dot between them
  version = ereg_replace( pattern:"([0-9])([A-Za-z])", string:version, replace:"\1.\2" );
  test_version = ereg_replace( pattern:"([0-9])([A-Za-z])", string:test_version, replace:"\1.\2" );

  if( debug ) display( 'DEBUG: version: ' + version + ' and test_version: ' + test_version + ' after adding dots' );

  # Split the versions into an array based on the ver_sep above
  ver_ary = split( version, sep:ver_sep, keep:FALSE );
  test_ary = split( test_version, sep:ver_sep, keep:FALSE );

  while( max_index( ver_ary ) < max_index( test_ary ) ) {
    ver_ary[max_index( ver_ary )] = "0";
  }

  while( max_index( ver_ary ) > max_index( test_ary ) ) {
    test_ary[max_index( test_ary )] = "0";
  }

  foreach _i( keys( test_ary ) ) {

    r = eregmatch( pattern:"([0-9]+)", string:test_ary[_i] );
    s = eregmatch( pattern:"([A-Za-z])", string:test_ary[_i] );
    test_prerelease = eregmatch( pattern:"(rc|alpha|beta)([0-9]+)", string:test_ary[_i], icase:TRUE );

    if( isnull( s ) ) {
      test_ary[_i] = int( r[0] ) * 128; # Changed to * 128 so if a char follows a number the number is more significant
      char_found = FALSE;
    } else {
      if( isnull( test_prerelease ) ) {
        test_ary[_i] = ( int( r[0] ) * 128 ) + ord( s[0] );
      } else {
        test_ary[_i] = test_prerelease[2];
      }
      char_found = TRUE;
    }

    r = eregmatch( pattern:"([0-9]+)", string:ver_ary[_i] );
    s = eregmatch( pattern:"([A-Za-z])", string:ver_ary[_i] );
    ver_prerelease = eregmatch( pattern:"(rc|alpha|beta)([0-9]+)", string:ver_ary[_i], icase:TRUE );

    if( isnull( s ) ) {
      ver_ary[_i] = int( r[0] ) * 128;
    } else if( char_found ) {
      if( isnull( ver_prerelease ) ) {
        ver_ary[_i] = ( int( r[0] ) * 128 ) + ord( s[0] );
      } else {
        ver_ary[_i] = ver_prerelease[2];
      }
    } else {
      if( isnull( r ) ) {
        ver_ary[_i] = ord( s[0] );
      } else {
        if( ! less )
          return FALSE; # If char found in test_version and no char in version it is not equal
        ver_ary[_i] = int( r[0] ) * 128; # No chars if test_version has no chars on this position else 1.1.1a is > 1.1.2
      }
    }

    if( less ) {
      if( ver_ary[_i] < test_ary[_i] )
        return TRUE;
      if( ver_ary[_i] > test_ary[_i] )
        return FALSE;
    } else {
      if( ver_ary[_i] != test_ary[_i] )
        return FALSE;
    }
  }
  if( less )
    return FALSE;
  else
    return TRUE;
}

# @deprecated Please register the product via @ref register_product and call e.g.
#             @ref get_app_version to get the version for a specific app.
#
function get_version_from_kb( port, app ) {

  local_var port, app;
  local_var version, matches, vers;

  if( ! port ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_version_from_kb" );
  if( ! app ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#get_version_from_kb" );

  if( isnull( port ) || isnull( app ) ) return FALSE;

  if( ! version = get_kb_item( "www/" + port + "/" + app ) ) return FALSE;
  if( ! matches = eregmatch( string:version, pattern:"^(.+) under (/.*)$" ) ) return FALSE;

  vers = matches[1];

  if( isnull( vers ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#vers#-#get_version_from_kb" );
    return FALSE;
  }

  if( vers == "unknown" || vers == "Unknown" ) return FALSE;

  return string( vers );
}

# @deprecated Please register the product via @ref register_product and call e.g.
#             @ref get_app_location to get the location for a specific app.
#
function get_dir_from_kb( port, app ) {

  local_var port, app;
  local_var version, matches, dir;

  if( ! port ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_dir_from_kb" );
  if( ! app ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#get_dir_from_kb" );

  if( isnull( port ) || isnull( app ) ) return FALSE;

  if( ! version = get_kb_item( "www/" + port + "/" + app ) ) return FALSE;
  if( ! matches = eregmatch( string:version, pattern:"^(.+) under (/.*)$" ) ) return FALSE;

  dir = matches[2];

  if( isnull( dir ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dir#-#get_dir_from_kb" );
    return FALSE;
  }
  return string( dir );
}
