###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Backup Exec Products Arbitrary Command Execution vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801798");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_cve_id("CVE-2011-0546");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_name("Symantec Backup Exec Products Arbitrary Command Execution vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47824");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_symantec_backup_exec_detect.nasl");
  script_mandatory_keys("Symantec/BackupExec/Win/Installed");

  script_tag(name:"insight", value:"The flaw is due to weakness in communication protocol implementation
  and lack of validation of identity information exchanged between media server and remote agent.");

  script_tag(name:"solution", value:"Upgrade to the Symantec Backup Exec 2010 R3");

  script_tag(name:"summary", value:"Symantec Backup Exec Products is prone to an arbitrary command execution vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause privilege
  escalation by executing post authentication NDMP commands.");

  script_tag(name:"affected", value:"Symantec Backup Exec for Windows Servers versions 11.0, 12.0, 12.5
  Symantec Backup Exec 2010 versions 13.0, 13.0 R2");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:symantec:veritas_backup_exec_for_windows_servers", "cpe:/a:symantec:backup_exec" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if( "cpe:/a:symantec:veritas_backup_exec_for_windows_servers" >< cpe ) {
  if( version_in_range( version:vers, test_version:"11.0", test_version2:"12.5.2213" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

else if( "cpe:/a:symantec:backup_exec" >< cpe ) {
  if( version_in_range( version:vers, test_version:"13.0", test_version2:"13.0.4164" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"13.0 R3", install_path:path );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
