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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902514");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2010-4792");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("OPEN IT OverLook 'title.php' Cross Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_overlook_detect.nasl");
  script_mandatory_keys("overlook/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary HTML and script code in a user's browser session in the context of an
affected site.");
  script_tag(name:"affected", value:"OPEN IT OverLook Version 5.0");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
passed via the 'frame' parameter to title.php, which allows attackers to execute
arbitrary HTML and script code in a user's browser session in the context of
an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"OverLook is prone to a cross-site scripting vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43872");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62361");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/94568/overlook-xss.txt");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:openit:overlook";

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_equal(version:vers, test_version:"5.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"WillNotFix");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
