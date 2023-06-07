# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:apereo:central_authentication_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806502");
  script_version("2022-09-30T10:11:44+0000");
  script_tag(name:"last_modification", value:"2022-09-30 10:11:44 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2015-10-19 13:02:46 +0530 (Mon, 19 Oct 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jasig Central Authentication Service (CAS) < 4.0.2 Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");

  script_family("Web application abuses");
  script_dependencies("gb_jasig_apereo_cas_consolidation.nasl");
  script_mandatory_keys("jasig_apereo/cas/http/detected");

  script_tag(name:"summary", value:"Jasig Central Authentication Service (CAS) is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - OpenID client does not validate input to the 'username' parameter while login before returning
  it to users.

  - OAuth server does not validate input to the 'redirect_uri' parameter before returning it to
  users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"Jasig Central Authentication Service (CAS) version 4.0.1 and
  prior.");

  script_tag(name:"solution", value:"Update to version 4.0.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Sep/88");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536510");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/openid/username"\nonmouseover="<script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\);</script>")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
