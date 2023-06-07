# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811576");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420", "CVE-2017-11423");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-08-08 14:13:11 +0530 (Tue, 08 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV <= 0.99.2 Multiple DoS Vulnerabilities - Linux");

  script_tag(name:"summary", value:"ClamAV is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper calidation for CHM file in 'mspack/lzxd.c' script in
    libmspack 0.5alpha.

  - An improper calidation for CAB file in cabd_read_string function in
    'mspack/cabd.c' script in libmspack 0.5alpha.

  - An improper validation for e-mail message in 'libclamav/message.c'
    script.

  - An improper validation for PE file in wwunpack function in
    'libclamav/wwunpack.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service or possibly have unspecified other
  impact.");

  script_tag(name:"affected", value:"ClamAV version 0.99.2 and prior.");

  script_tag(name:"solution", value:"Update to version 0.99.3-beta1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/vrtadmin/clamav-devel/commit/a83773682e856ad6529ba6db8d1792e6d515d7f1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100154");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"0.99.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.99.3-beta1", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
