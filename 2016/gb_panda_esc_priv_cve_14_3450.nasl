###############################################################################
# OpenVAS Vulnerability Test
#
# Privilege Escalation in Panda Gold Protection 2014 CVE-2014-3450 (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:pandasecurity:panda_gold_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107091");
  script_version("2021-10-15T11:13:32+0000");
  script_cve_id("CVE-2014-3450");
  script_tag(name:"last_modification", value:"2021-10-15 11:13:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-18 09:18:47 +0100 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Panda Gold Protection 2014 Privilege Escalation Vulnerability (CVE-2014-3450) - Windows");
  script_xref(name:"URL", value:"http://www.anti-reversing.com/cve-2014-3450-privilege-escalation-in-panda-security/");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-3450/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GoldProtection/Ver");

  script_tag(name:"affected", value:"Panda Gold Protection 2014 version 7.01.01 and prior.");

  script_tag(name:"insight", value:"As the USERS group has write permissions over the folder where
  the PSEvents.exe process is located, it is possible to execute malicious code as Local System.");

  script_tag(name:"solution", value:"Install Panda Hotfix for this vulnerability, see the vendor
  advisory.");

  script_tag(name:"summary", value:"Panda Gold Protection 2014 is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"impact", value:"This vulnerability allows for privilege escalation on the local
  system.");

  script_tag(name:"qod", value:"30");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"7.01.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );