# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.814147");
  script_version("2022-03-01T12:03:40+0000");
  script_cve_id("CVE-2018-15378");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-03-01 12:03:40 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-17 15:04:36 +0530 (Wed, 17 Oct 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV < 0.100.2 'unmew11()' DoS Vulnerability - Linux");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw related to the MEW unpacker within
  the 'unmew11()' function (libclamav/mew.c) can be exploited to trigger an
  invalid read memory access via a specially crafted EXE file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service.");

  script_tag(name:"affected", value:"ClamAV versions before 0.100.2.");

  script_tag(name:"solution", value:"Update to version 0.100.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=12170");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"0.100.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.100.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
