# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:nulllogic:groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800906");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2354", "CVE-2009-2355", "CVE-2009-2356");
  script_name("NullLogic Groupware <= 1.2.7 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nulllogic_groupware_http_detect.nasl", "gb_nulllogic_groupware_ssh_login_detect.nasl");
  script_mandatory_keys("nulllogic/groupware/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35606");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51592");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51593");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504737/100/0/threaded");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary
  SQL quries in the context of affected application, and can cause buffer overflow or
  a denial of service.");

  script_tag(name:"affected", value:"NullLogic Groupware 1.2.7 and prior.");

  script_tag(name:"insight", value:"Multiple flaws exist because:

  - The 'auth_checkpass' function in the login page does not validate the input passed
  into the username parameter.

  - An error in the 'fmessagelist' function in the forum module when processing a group
  name containing a non-numeric string or is an empty string.

  - Multiple stack-based buffer overflows occurs in the 'pgsqlQuery' function while
  processing malicious input to POP3, SMTP or web component that triggers a long SQL query
  when PostgreSQL is used.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NullLogic Groupware is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"1.2.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
