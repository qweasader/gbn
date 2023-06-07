###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress MU Cross-Site Scripting Vulnerability - Apr09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wordpress:wordpress_mu";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800376");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1030");
  script_name("WordPress MU Cross-Site Scripting Vulnerability - Apr09");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34075");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49184");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021838.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute malicious crafted
  HTTP headers and conduct cross site scripting attacks to gain administrative
  privileges into the affected web application.");

  script_tag(name:"affected", value:"WordPress MU before 2.7 on all running platform.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of user supplied input in
  'wp-includes/wpmu-functions.php' for choose_primary_blog function.");

  script_tag(name:"solution", value:"Update to Version 2.7 or later.");

  script_tag(name:"summary", value:"WordPress MU is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpmuPort = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:wpmuPort))
  exit(0);

if(version_is_less(version:ver, test_version:"2.7")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.7");
  security_message(port:wpmuPort, data:report);
  exit(0);
}

exit(99);