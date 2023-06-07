###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Workstation 'vmrun' Library Path Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801912");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-1126");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Workstation 'vmrun' Library Path Privilege Escalation Vulnerability (VMSA-2011-0006) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1025270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47094");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0006.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code with elevated privileges, which may aid in other attacks.");

  script_tag(name:"affected", value:"VMware Workstation 6.5.x and 7.x before 7.1.4 build 385536.");

  script_tag(name:"insight", value:"The flaw is caused by an error in the 'vmrun' utility when
  handling library paths, which could be exploited to execute arbitrary code by tricking a user into
  running a vulnerable utility in a directory containing a specially crafted file.");

  script_tag(name:"summary", value:"VMware Workstation is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or update to Workstation 7.1.4 build 385536.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:vmware:workstation";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "6.5", test_version2: "6.5.5" ) ||
   version_in_range( version: version, test_version: "7.0", test_version2: "7.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1.4" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
