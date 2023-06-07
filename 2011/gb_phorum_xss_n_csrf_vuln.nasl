# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:phorum:phorum";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802160");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-3381", "CVE-2011-3382");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Phorum < 5.2.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phorum_http_detect.nasl");
  script_mandatory_keys("phorum/detected");

  script_tag(name:"summary", value:"Phorum is prone to cross-site scripting (XSS) and cross-site
  request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code in the context of an application.");

  script_tag(name:"affected", value:"Phorum prior to version 5.2.16.");

  script_tag(name:"solution", value:"Update to version 5.2.16 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN71435255/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000068.html");

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

if (version_is_less(version: version, test_version: "5.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
