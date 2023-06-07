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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145473");
  script_version("2021-08-26T06:01:00+0000");
  script_tag(name:"last_modification", value:"2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-03-02 04:31:01 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-08 17:48:00 +0000 (Mon, 08 Mar 2021)");

  script_cve_id("CVE-2018-25004");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB DoS Vulnerability (SERVER-38275) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user authorized to performing a specific type of query may trigger a
  denial of service by issuing a generic explain command on a find query.");

  script_tag(name:"affected", value:"MongoDB versions 3.6.x - 3.6.11, 4.0.x - 4.0.5 and 4.1.x - 4.1.6.");

  script_tag(name:"solution", value:"Update to version 3.6.11, 4.0.6, 4.1.7 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-38275");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.6.0", test_version2: "3.6.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
