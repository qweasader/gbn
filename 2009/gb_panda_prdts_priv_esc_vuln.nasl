###############################################################################
# OpenVAS Vulnerability Test
#
# Panda Products Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801080");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4215");
  script_name("Panda Products 'CVE-2009-4215' Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37373");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1023121");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3126");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507811/100/0/threaded");
  script_xref(name:"URL", value:"http://www.pandasecurity.com/homeusers/support/card?id=80164&idIdioma=2");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/Products/Installed");

  script_tag(name:"affected", value:"Panda AntiVirus Pro 2010 version 9.01.00 and prior.

  Panda Internet Security 2010 version 15.01.00 and prior.

  Panda Global Protection 2010 version 3.01.00 and prior.");

  script_tag(name:"insight", value:"This flaw is due to insecure permissions being set on the 'PavFnSvr.exe'
  file (Everyone/Full Control) within the installation directory, which could be
  exploited by malicious users to replace the affected file with a malicious
  binary which will be executed with SYSTEM privileges.");

  script_tag(name:"solution", value:"Apply the security updates from the linked references.");

  script_tag(name:"summary", value:"panda Products is prone to a privilege escalation vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker replace the affected binary file
  with a malicious binary which will be executed with SYSTEM privileges.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:pandasecurity:panda_av_pro_2010", "cpe:/a:pandasecurity:panda_internet_security_2010", "cpe:/a:pandasecurity:panda_global_protection_2010" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if( "cpe:/a:pandasecurity:panda_av_pro_2010" >< cpe ) {
  if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.01.00" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

else if( "cpe:/a:pandasecurity:panda_internet_security_2010" >< cpe ) {
  if( version_in_range( version:vers, test_version:"15.0", test_version2:"15.01.00" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

else if( "cpe:/a:pandasecurity:panda_global_protection_2010" >< cpe ) {
  if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.01.00" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
