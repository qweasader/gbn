###############################################################################
# OpenVAS Vulnerability Test
#
# Omron CX-Programmer Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113308");
  script_version("2021-01-15T07:13:31+0000");
  script_tag(name:"last_modification", value:"2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2018-12-06 12:16:30 +0100 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Omron CX-Programmer Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of Omron CX-Programmer.");

  script_xref(name:"URL", value:"https://industrial.omron.eu/en/products/cx-programmer");

  exit(0);
}

CPE = "cpe:/a:omron:cx-programmer:";

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("list_array_func.inc");

base_key_one = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
base_key_two = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach keypart( make_list_unique( registry_enum_keys( key: base_key_one ), registry_enum_keys( key: base_key_two ) ) ) {

  key = base_key_one + keypart;
  if( ! registry_key_exists( key: key ) ) {
    key = base_key_two + keypart;
    if( ! registry_key_exists( key: key ) ) continue;
  }

  name = registry_get_sz( key: key, item: "DisplayName" );
  if( name !~ '^CX[- ]Programmer' ) continue;
  set_kb_item( name: "omron/cx-programmer/detected", value: TRUE );
  version = "unknown";

  # For future notice, thought I'd add it here:
  # If one day a customer remarks that this doesn't detect the version reliably
  # (maybe because Omron changes how they set their registry keys)
  # The items "VersionMajor" and "VersionMinor" will contain hex-representations
  # of the major, respectively minor, version.

  vers = registry_get_sz( key: key, item: "DisplayVersion" );
  if( ! isnull( vers ) && vers != "" ) {
    version = vers;
    set_kb_item( name: "omron/cx-programmer/version", value: version );
  }

  insloc = registry_get_sz( key: key, item: "InstallLocation" );

  register_and_report_cpe( app: "Omron CX-Programmer",
                           ver: version,
                           concluded: version,
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: insloc,
                           regService: "smb-login" );

  exit( 0 );
}

exit( 0 );
