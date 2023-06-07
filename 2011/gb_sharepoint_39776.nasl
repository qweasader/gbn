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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103254");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0817");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SharePoint Server 2007 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sharepoint/banner");

  script_tag(name:"summary", value:"Microsoft SharePoint Server 2007 and SharePoint Services 3.0
  are prone to a cross-site scripting (XSS) vulnerability because they fail to properly sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution", value:"The vendor has released an advisory and updates. Please see the
  references for details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39776");
  script_xref(name:"URL", value:"http://blogs.technet.com/msrc/archive/2010/04/29/security-advisory-983438-released.aspx");
  script_xref(name:"URL", value:"http://office.microsoft.com/en-us/sharepointserver/FX100492001033.aspx");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511021");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100089744");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/983438");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-039");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_asp(port: port))
  exit(0);

banner = http_get_remote_headers(port: port);
if (!banner || "sharepoint" >!< tolower(banner))
  exit(0);

url = "/_layouts/help.aspx?cid0=MS.WSS.manifest.xml%00%3Cscript%3Ealert%28%27VT-XSS-Test%27%29%3C/script%3E&tid=X";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('VT-XSS-Test'\)</script><br/>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
