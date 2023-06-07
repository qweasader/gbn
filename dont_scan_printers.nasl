###############################################################################
# OpenVAS Vulnerability Test
#
# Do not scan printers
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 by Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11933");
  script_version("2021-03-17T14:33:36+0000");
  script_tag(name:"last_modification", value:"2021-03-17 14:33:36 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Do not scan printers");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2005 by Michel Arboi");
  script_family("Settings");
  script_dependencies("global_settings.nasl", "dont_print_on_printers.nasl");
  script_mandatory_keys("global_settings/exclude_printers", "Host/is_printer");

  script_tag(name:"summary", value:"The host seems to be a printer. The scan has been
  disabled against this host.");

  script_tag(name:"solution", value:"If you want to scan the remote host, uncheck the
  'Exclude printers from scan' option within the 'Global variable settings' of the scan
  config in use and re-scan it.");

  script_tag(name:"insight", value:"Many printers react very badly to a network scan. Some
  of them will crash, while others will print a number of pages. This usually disrupt
  office work and is usually a nuisance. As a result, the scan has been disabled against
  this host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( get_kb_item( "Host/scanned" ) == 0 )
  exit( 0 );

if( ! get_kb_item( "Host/is_printer" ) )
  exit( 0 );

pref = get_kb_item( "global_settings/exclude_printers" );

if( pref && pref != "no" ) {
  report = get_kb_item( "Host/is_printer/reason" );
  if( report )
    report = 'Exclusion reason:\n\n' + report;
  log_message( port:0, data:report );
  set_kb_item( name:"Host/dead", value:TRUE );
}

exit( 0 );