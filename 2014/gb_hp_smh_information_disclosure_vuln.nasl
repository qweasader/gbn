# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804415");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2013-4846");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-03-19 13:14:25 +0530 (Wed, 19 Mar 2014)");
  script_name("HP/HPE System Management Homepage (SMH) Information Disclosure Vulnerability (HPSBMU02947)");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unspecified error can be exploited to disclose certain
  information. No further information is currently available.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose certain
  information.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.3.");

  script_tag(name:"solution", value:"Update to version 7.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66129");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Mar/61");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c04039138");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);