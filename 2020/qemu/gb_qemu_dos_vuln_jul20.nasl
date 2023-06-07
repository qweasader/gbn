# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113725");
  script_version("2021-07-22T11:01:40+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-07-16 09:13:23 +0000 (Thu, 16 Jul 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 19:17:00 +0000 (Wed, 24 Feb 2021)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15469");

  script_name("QEMU <= 4.2.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_qemu_detect_lin.nasl");
  script_mandatory_keys("QEMU/Lin/Ver");

  script_tag(name:"summary", value:"QEMU is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A MemoryRegionOps object lacks read/write callback methods,
  leading to a NULL pointer dereference.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");

  script_tag(name:"affected", value:"QEMU through version 4.2.0.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/07/02/1");
  script_xref(name:"URL", value:"https://lists.gnu.org/archive/html/qemu-devel/2020-06/msg09961.html");

  exit(0);
}

CPE = "cpe:/a:qemu:qemu";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.2.1", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
