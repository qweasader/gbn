###############################################################################
# OpenVAS Vulnerability Test
#
# Pligg Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801258");
  script_version("2022-05-02T09:35:37+0000");
  script_cve_id("CVE-2010-2577", "CVE-2010-3013");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_name("Pligg Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42408");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-111/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("pligg_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pligg/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"Pligg CMS Version 1.1.0 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied inputs via the
  'title' parameter in storyrss.php and story.php and 'role' parameter in
  groupadmin.php that allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Pligg CMS Version 1.1.1 or later.");

  script_tag(name:"summary", value:"Pligg CMS is prone to multiple SQL injection vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(ver = get_version_from_kb(port:port, app:"pligg"))
{
  if(version_is_less(version:ver, test_version:"1.1.1")){
    report = report_fixed_ver(installed_version:ver, fixed_version:"1.1.1");
    security_message(port: port, data: report);
  }
}
