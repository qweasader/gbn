# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:pandasecurity:panda_internet_security_2014";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107090");
  script_version("2022-02-09T12:06:17+0000");
  script_tag(name:"last_modification", value:"2022-02-09 12:06:17 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-11-21 09:18:47 +0100 (Mon, 21 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Panda Internet Security <= 16.1.2 Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/InternetSecurity/Ver");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40020/");
  script_xref(name:"URL", value:"https://www.pandasecurity.com/en/support/card?id=100053");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Panda Internet Security version 16.1.2 and prior.");

  script_tag(name:"insight", value:"As the USERS group has write permissions over the folder where
  the PSEvents.exe process is located, it is possible to execute malicious code as Local System.");

  script_tag(name:"solution", value:"Install the hotfix for this vulnerability linked in the
  references.");

  script_tag(name:"summary", value:"Panda Internet Security is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker replace the
  affected binary file with a malicious binary which will be executed with SYSTEM privileges.");

  # nb: Hotfix not detected
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

if( version_is_less_equal( version:vers, test_version:"16.01.02" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
