# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145708");
  script_version("2022-02-08T15:04:53+0000");
  script_tag(name:"last_modification", value:"2022-02-08 15:04:53 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"creation_date", value:"2021-04-13 06:01:00 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 18:17:00 +0000 (Fri, 04 Jun 2021)");

  script_cve_id("CVE-2021-28657");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika Server < 1.26 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  script_tag(name:"summary", value:"Apache Tika Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A carefully crafted or corrupt file may trigger an infinite loop in Tika's
  MP3Parser.");

  script_tag(name:"affected", value:"Apache Tika version 1.25 and prior.");

  script_tag(name:"solution", value:"Update to version 1.26 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r915add4aa52c60d1b5cf085039cfa73a98d7fae9673374dfd7744b5a%40%3Cdev.tika.apache.org%3E");

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

if (version_is_less(version: version, test_version: "1.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
