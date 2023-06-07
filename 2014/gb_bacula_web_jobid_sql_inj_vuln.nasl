###############################################################################
# OpenVAS Vulnerability Test
#
# Bacula-web 'jobid' Parameter SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804771");
  script_version("2021-03-11T10:58:32+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2014-10-07 11:01:51 +0530 (Tue, 07 Oct 2014)");

  script_cve_id("CVE-2014-8295");

  script_name("Bacula-Web 'jobid' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Bacula-Web is prone to an SQL injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"Flaw is due to the joblogs.php script not
  properly sanitizing user-supplied input to the 'jobid' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to manipulate SQL queries in the backend database, and disclose certain
  sensitive information.");

  script_tag(name:"affected", value:"Bacula-Web version 5.2.10. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"Update to Bacula-Web version 6.0.1
  or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34851");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128480");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/bacula-web", "/baculaweb", "/bacula", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/test.php", port:port);

  if(">bacula-web<" >< res && ">Dashboard<" >< res) {
    url = dir + "/joblogs.php?jobid='SQL-Injection-Test";

    if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"You have an error in your SQL syntax.*SQL-Injection-Test")) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
