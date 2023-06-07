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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902773");
  script_version("2021-09-01T07:45:06+0000");
  script_cve_id("CVE-2011-4752", "CVE-2011-4751", "CVE-2011-4750");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-12-21 16:43:05 +0530 (Wed, 21 Dec 2011)");
  script_tag(name:"last_modification", value:"2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)");
  script_name("SmarterTools SmarterStats Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9999);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.smartertools.com/smarterstats/web-analytics-seo-software.aspx");
  script_xref(name:"URL", value:"http://xss.cx/examples/exploits/stored-reflected-xss-cwe79-smarterstats624100.html");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"SmarterTools SmarterStats version 6.2.4100.");

  script_tag(name:"insight", value:"The flaws are due to an:

  - Input passed via multiple parameters to multiple scripts are not properly
  sanitised before being returned to the user.

  - Error in 'frmGettingStarted.aspx' generates response with GET request,
  which allows remote attackers obtain sensitive information by reading
  web-server access logs or and web-server referer logs.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is SmarterTools SmarterStats and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:9999);
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

res = http_get_cache(item: "/login.aspx", port:port);

if("Login to SmarterStats" >< res || ">SmarterStats" >< res) {
  ver = eregmatch(pattern:">SmarterStats.?([a-zA-Z]+?.?([0-9.]+))", string:res);
  if(ver[2] =~ "^[0-9]"){
    ver = ver[2];
  } else{
    ver = ver[1];
  }
}

if(ver) {
  if(version_in_range(version:ver, test_version:"6.2", test_version2:"6.2.4100")){
    security_message(port);
  }
}
