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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145505");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-03-05 04:25:44 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-09 15:09:00 +0000 (Tue, 09 Mar 2021)");

  script_cve_id("CVE-2021-26027", "CVE-2021-26028", "CVE-2021-23132");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.9.24 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - ACL violation within com_content frontend editing. (CVE-2021-26027)

  - Path Traversal within joomla/archive zip class. (CVE-2021-26028)

  - com_media allowed paths that are not intended for image. (CVE-2021-23132)");

  script_tag(name:"affected", value:"Joomla! version 3.0.0 through 3.9.24.");

  script_tag(name:"solution", value:"Update to version 3.9.25 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/847-20210307-core-acl-violation-within-com-content-frontend-editing.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/848-20210308-core-path-traversal-within-joomla-archive-zip-class.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/846-20210306-core-com-media-allowed-paths-that-are-not-intended-for-image-uploads.html");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.25", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
