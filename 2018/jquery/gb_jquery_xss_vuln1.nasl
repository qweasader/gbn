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

CPE = "cpe:/a:jquery:jquery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141635");
  script_version("2021-06-11T08:43:18+0000");
  script_tag(name:"last_modification", value:"2021-06-11 08:43:18 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-11-01 15:57:33 +0700 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-08 12:15:00 +0000 (Fri, 08 Jan 2021)");

  script_cve_id("CVE-2015-9251");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("jQuery < 3.0.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jquery_consolidation.nasl");
  script_mandatory_keys("jquery/detected");

  script_tag(name:"summary", value:"jQuery is vulnerable to Cross-site Scripting (XSS) attacks.");

  script_tag(name:"insight", value:"When a cross-domain Ajax request is performed without the
  dataType option, causing text/javascript responses to be executed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"jQuery prior to version 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.0 or later or apply the patch.");

  script_xref(name:"URL", value:"https://github.com/jquery/jquery/issues/2432");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "3.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0", install_path: infos["location"]);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);