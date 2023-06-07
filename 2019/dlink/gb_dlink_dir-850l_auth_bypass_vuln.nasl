# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113332");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-02-07 14:51:44 +0100 (Thu, 07 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-28 18:57:00 +0000 (Tue, 28 Jun 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-18907");

  script_name("D-Link DIR-850L FW < 1.21B07 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-850L is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is installed on the
  target device.");

  script_tag(name:"insight", value:"The vulnerability exists due to the router allowing clients to
  communicate with it without completing the full WPA handshake.");

  script_tag(name:"impact", value:"Successful exploitation would allow an unauthenticated attacker to
  register as a client in the router's network.");

  script_tag(name:"affected", value:"D-Link DIR-850L all revision A devices with firmware version
  1.21B06 and prior.");

  script_tag(name:"solution", value:"Update to firmware version 1.21B07.");

  script_xref(name:"URL", value:"https://www.synopsys.com/blogs/software-security/cve-2018-18907/");

  exit(0);
}

CPE = "cpe:/o:d-link:dir-850l_firmware";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! fw_vers = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

# e.g. A1
if( ! hw_vers = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

hw_vers = toupper( hw_vers );
fw_vers = toupper( fw_vers );

if( hw_vers =~ "^A" && version_is_less( version: fw_vers, test_version: "1.21B07" ) ) {
  report = report_fixed_ver( installed_version: fw_vers, fixed_version: "1.21B07", extra: "Hardware revision: " + hw_vers );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
