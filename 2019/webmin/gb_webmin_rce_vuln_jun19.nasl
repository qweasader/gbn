# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113409");
  script_version("2021-09-08T08:01:40+0000");
  script_tag(name:"last_modification", value:"2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-06-17 10:11:59 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-12840");

  script_name("Webmin <= 1.941 Remote Code Execution (RCE) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("usermin_or_webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user authorized to the 'Package Updates' module can execute arbitrary
  commands with root privileges via the data parameter to update.cgi.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authorized attacker to gain
  control over the target system.");

  script_tag(name:"affected", value:"Webmin through version 1.941.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  # Note: Vendor does not accept the vulnerability as workable exploit, because it requires that the attacker
  # already knows the root password. Hence there will be no fix for it in Webmin.
  script_xref(name:"URL", value:"https://pentest.com.tr/exploits/Webmin-1910-Package-Updates-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46984");

  exit(0);
}

CPE = "cpe:/a:webmin:webmin";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.941" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 0 );
