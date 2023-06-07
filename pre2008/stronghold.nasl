# OpenVAS Vulnerability Test
# Description: Redhat Stronghold File System Disclosure
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Changes by rd: re-wrote the code to do pattern matching
#
# Copyright:
# Copyright (C) 2001 Felix Huber
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10803");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3577");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Redhat Stronghold Secure Server File System Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Felix Huber");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"In Redhat Stronghold from versions 2.3 up to 3.0 a flaw
  exists that allows a remote attacker to disclose sensitive system files including the
  httpd.conf file, if a restricted access to the server status report is not enabled when
  using those features.");

  script_tag(name:"impact", value:"This may assist an attacker in performing further attacks.

  By trying the following URLs, an attacker can gather sensitive information:

  http://example.com/stronghold-info will give information on configuration

  http://example.com/stronghold-status will return among other information the list of
  request made

  Please note that this attack can be performed after a default installation. The
  vulnerability seems to affect all previous version of Stronghold.");

  script_tag(name:"solution", value:"The vendor has released an update on November 19, 2001.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/stronghold-info";
res = http_get_cache(item:url, port:port);
if(res && "Stronghold Server Information" >< res) {
  VULN = TRUE;
  report += '\n' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
}

url = "/stronghold-status";
res = http_get_cache(item:url, port:port);
if(res && "Stronghold Server Status for" >< res) {
  VULN = TRUE;
  report += '\n' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
}

if(VULN) {
  security_message(port:port, data:"The following URLs are exposed:" + report);
  exit(0);
}

exit(99);
