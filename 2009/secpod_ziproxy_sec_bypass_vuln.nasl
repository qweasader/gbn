# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900523");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0804");
  script_name("Ziproxy Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34018/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33858");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/435052");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("secpod_ziproxy_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Ziproxy/installed");

  script_tag(name:"impact", value:"This can be exploited to restrict websites or bypass a browser's
  security context protection mechanism by sending HTTP requests with
  forged HTTP Host header.");

  script_tag(name:"affected", value:"Ziproxy version 2.6.0 and prior on Linux.");

  script_tag(name:"insight", value:"This vulnerability arises because ziproxy depends on HTTP Host headers
  to determine the remote endpoints while acting as a transparent proxy.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Ziproxy version 3.1.0 or later.");

  script_tag(name:"summary", value:"Ziproxy server is prone to a security bypass vulnerability.");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

zipPort = http_get_port( default:8080 );

ziproxyVer = get_kb_item("www/" + zipPort + "/Ziproxy");
if(!ziproxyVer){
  exit(0);
}

if(version_is_less_equal(version:ziproxyVer, test_version:"2.6.0")){
  report = report_fixed_ver(installed_version:ziproxyVer, vulnerable_range:"Less than or equal to 2.6.0");
  security_message(port: zipPort, data: report);
}
