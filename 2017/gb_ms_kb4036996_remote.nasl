# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:microsoft:sql_server:2014:sp2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811290");
  script_version("2022-10-27T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-10-27 10:11:07 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"creation_date", value:"2017-08-09 15:20:35 +0530 (Wed, 09 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-27 01:04:00 +0000 (Thu, 27 Oct 2022)");

  script_cve_id("CVE-2017-8516");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL Server Information Disclosure Vulnerability (KB4036996)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("mssqlserver_detect.nasl");
  script_mandatory_keys("microsoft/sqlserver/detected");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft SQL Server Analysis Services improperly enforces
  permissions.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2014 Service Pack 2 for x86/x64-based Systems (CU).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4036996");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100041");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!vers = get_kb_item("microsoft/sqlserver/" + port + "/version"))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(version_in_range(version:vers, test_version:"12.0.5400.0", test_version2:"12.0.5552.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"12.0.5400.0 - 12.0.5552.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
