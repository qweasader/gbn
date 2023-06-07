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

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114126");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-09-03 14:13:30 +0200 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-30 15:47:00 +0000 (Thu, 30 Nov 2017)");

  script_cve_id("CVE-2015-8793");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.0.6, 1.1.x < 1.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This XSS vulnerability allows remote attackers to inject
  arbitrary web scripts or HTML via the _mbox parameter in a mail task to the default URL.");

  script_tag(name:"affected", value:"Roundcube Webmail versions before 1.0.6 and 1.1.x before
  1.1.2.");

  script_tag(name:"solution", value:"Update to version 1.0.6, 1.1.2 or later.");

  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/issues/4837");
  script_xref(name:"URL", value:"https://roundcube.net/news/2015/06/05/updates-1.1.2-and-1.0.6-released");
  script_xref(name:"URL", value:"https://github.com/roundcube/roundcubemail/wiki/Changelog#Release1.1.2");

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

if (version_is_less(version: version, test_version: "1.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
