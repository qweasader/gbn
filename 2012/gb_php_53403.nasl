# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103486");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2012-1172");
  script_version("2022-04-27T12:01:52+0000");
  script_name("PHP Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53403");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=799187");
  script_xref(name:"URL", value:"http://www.php.net/archive/2012.php#id2012-04-26-1");

  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-05-08 11:25:16 +0200 (Tue, 08 May 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to retrieve, corrupt or
  upload arbitrary files at arbitrary locations that could aid in further attacks.");

  script_tag(name:"affected", value:"PHP version before 5.3.10 and 5.4.x including 5.4.0");

  script_tag(name:"insight", value:"Remote attackers can use specially crafted requests with directory-
  traversal sequences ('../') to retrieve, corrupt or upload arbitrary
  files in the context of the application.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"PHP is prone to a directory-traversal vulnerability because it fails
  to properly sanitize user-supplied input.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.4", test_version2:"5.4.0") ||
   version_in_range(version:vers, test_version:"5.3", test_version2:"5.3.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.10/5.4.1");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
