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
  script_oid("1.3.6.1.4.1.25623.1.0.113544");
  script_version("2022-02-16T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-02-16 03:03:58 +0000 (Wed, 16 Feb 2022)");
  script_tag(name:"creation_date", value:"2019-10-21 15:50:34 +0000 (Mon, 21 Oct 2019)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-14 17:35:00 +0000 (Mon, 14 Feb 2022)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16301");

  script_name("libpcap < 1.9.1 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_tcpdump_ssh_detect.nasl");
  script_mandatory_keys("libpcap/detected");

  script_tag(name:"summary", value:"libpcap is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because of errors in pcapng reading.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"libpcap through version 1.9.0.");

  script_tag(name:"solution", value:"Update to version 1.9.1.");

  script_xref(name:"URL", value:"https://www.tcpdump.org/libpcap-changes.txt");

  exit(0);
}

CPE = "cpe:/a:tcpdump:libpcap";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.9.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.9.1", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
