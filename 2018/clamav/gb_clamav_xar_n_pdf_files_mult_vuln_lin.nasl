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
  script_oid("1.3.6.1.4.1.25623.1.0.812578");
  script_version("2022-03-01T12:03:40+0000");
  script_cve_id("CVE-2018-0202", "CVE-2018-1000085");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-03-01 12:03:40 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 16:02:00 +0000 (Tue, 26 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-03-21 11:16:51 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV <= 0.99.3 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities - Linux");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An incorrectly handled parsing certain PDF files

  - An incorrectly handled parsing certain XAR files");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service and potentially execute arbitrary code
  on the affected device.");

  script_tag(name:"affected", value:"ClamAV version 0.99.3 and prior.");

  script_tag(name:"solution", value:"Update to version 0.99.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav-devel/commit/d96a6b8bcc7439fa7e3876207aa0a8e79c8451b6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
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

if(version_is_less(version:vers, test_version:"0.99.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.99.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);