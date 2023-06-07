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

CPE = "cpe:/a:kentico:kentico";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142266");
  script_version("2021-12-07T13:21:50+0000");
  script_tag(name:"last_modification", value:"2021-12-07 13:21:50 +0000 (Tue, 07 Dec 2021)");
  script_tag(name:"creation_date", value:"2019-04-16 07:53:03 +0000 (Tue, 16 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-11 16:06:00 +0000 (Thu, 11 Apr 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-19453");

  script_name("Kentico CMS < 11.0.45 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_http_detect.nasl");
  script_mandatory_keys("kentico_cms/detected");

  script_tag(name:"summary", value:"Kentico CMS allows unrestricted upload of a file with a
  dangerous type.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for a malicious attacker to upload dangerous file
  types to perform attacks such as Cross-Site Scripting (XSS) and Cross-Origin Resource Sharing
  (CORS) attacks.");

  script_tag(name:"affected", value:"Kentico CMS prior to version 11.0.45.");

  script_tag(name:"solution", value:"Update to version 11.0.45 or later.");

  script_xref(name:"URL", value:"https://blog.hivint.com/advisory-upload-malicious-file-in-kentico-cms-cve-2018-19453-36debbf85216");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "11.0.45")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.45", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);