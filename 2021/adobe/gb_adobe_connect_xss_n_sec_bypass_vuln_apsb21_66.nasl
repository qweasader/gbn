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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818503");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-36061", "CVE-2021-36062", "CVE-2021-36063", "CVE-2021-40719",
                "CVE-2021-40721");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-28 14:01:13 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 02:23:00 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 00:05:37 +0530 (Fri, 13 Aug 2021)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities (APSB21-66, APSB21-91)");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple input
  validation errors and violation of secure design principles in Adobe Connect
  software.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and bypass security restrictions.");

  script_tag(name:"affected", value:"Adobe Connect versions 11.2.2 and earlier.");

  script_tag(name:"solution", value:"Update Adobe Connect to version 11.2.3 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-66.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb21-91.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.2.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.2.3", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);
