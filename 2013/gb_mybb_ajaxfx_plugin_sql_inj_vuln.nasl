##############################################################################
# OpenVAS Vulnerability Test
#
# MyBB Ajaxfs Plugin 'usertooltip' Parameter SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:mybb:mybb';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803966");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-6936");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-11-22 11:50:32 +0530 (Fri, 22 Nov 2013)");
  script_name("MyBB Ajaxfs Plugin 'usertooltip' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"MyBB Ajaxfs Plugin Version 2.0, Other versions may also be affected.");
  script_tag(name:"insight", value:"The flaw is due to input passed via the 'usertooltip' parameter to
  'ajaxfs.php', which is not properly sanitised before being used in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query.");

  script_tag(name:"summary", value:"MyBB with Ajaxfs Plugin is prone to an SQL injection (SQLi) vulnerability.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63818");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/529907");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/ajaxfs.php?usertooltip=1'";

if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"MyBB has experienced an internal SQL error and cannot continue.", extra_check:"You have an error in your SQL syntax")){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}

exit(0);
