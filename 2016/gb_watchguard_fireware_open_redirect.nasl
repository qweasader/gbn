# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/o:watchguard:fireware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106080");
  script_version("2022-03-01T03:54:49+0000");
  script_tag(name:"last_modification", value:"2022-03-01 03:54:49 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-05-20 11:08:44 +0700 (Fri, 20 May 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WatchGuard Fireware XTM < 11.10.7 Open Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_watchguard_firebox_consolidation.nasl");
  script_mandatory_keys("watchguard/firebox/detected");

  script_tag(name:"summary", value:"WatchGuard Fireware XMT Web UI is prone to an open redirect
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An open redirect vulnerability has been detected in the login
  form.");

  script_tag(name:"impact", value:"A remote user can create a URL that, when loaded by the target
  user, will exploit an input validation flaw in the management Web UI authentication form and
  redirect the target user's browser to an arbitrary site.");

  script_tag(name:"affected", value:"WatchGuard Fireware XTM prior to version 11.10.7.");

  script_tag(name:"solution", value:"Update to version 11.10.7 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Apr/22");
  script_xref(name:"URL", value:"https://www.watchguard.com/support/release-notes/fireware/11/en-US/#Fireware/en-US/resolved_issues.html?TocPath=_____11");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "11.10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.10.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
