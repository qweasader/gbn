###############################################################################
# OpenVAS Vulnerability Test
#
# Varnish Log Escape Sequence Injection  Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800447");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4488");
  script_name("Varnish Log Escape Sequence Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.ush.it/team/ush/hack_httpd_escape/adv.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37713");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508830/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_varnish_detect.nasl");
  script_mandatory_keys("Varnish/Ver");

  script_tag(name:"affected", value:"Varnish version 2.0.6 and prior.");

  script_tag(name:"insight", value:"The flaw exists when the Web Server is executed in foreground in a pty or
  when the logfiles are viewed with tools like 'cat' or 'tail' injected control
  characters reach the terminal and are executed.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Varnish version 2.1.2 or later.");

  script_tag(name:"summary", value:"Varnish is prone to Log Escape Sequence Injection Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary commands in
  a terminal.");

  exit(0);
}

include("version_func.inc");

varVer = get_kb_item("Varnish/Ver");
if(!varVer)
  exit(0);

if(version_is_less_equal(version:varVer, test_version:"2.0.6")){
  report = report_fixed_ver(installed_version:varVer, vulnerable_range:"Less than or equal to 2.0.6");
  security_message(port: 0, data: report);
}
