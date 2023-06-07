# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114081");
  script_version("2022-12-02T10:11:16+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-02 10:11:16 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"creation_date", value:"2019-03-12 13:52:47 +0100 (Tue, 12 Mar 2019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_name("Xiongmai Net Surveillance Authentication Bypass");
  script_dependencies("gb_xiongmai_net_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xiongmai/net_surveillance/detected", "xiongmai/net_surveillance/version");

  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/xc3511/");

  script_tag(name:"summary", value:"The remote installation of Xiongmai Net Surveillance is prone to
  an authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information through the camera feed or to get access to a potentially vulnerable version.");

  script_tag(name:"insight", value:"The installation of Xiongmai Net Surveillance allows any attacker to
  bypass the login screen to get full access to the camera feed and the version number.");

  script_tag(name:"vuldetect", value:"Checks if the /DVR.html page is accessible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

CPE = "cpe:/a:xiongmai:net_surveillance";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE)) # nb: To have a reference to the Detection-VT
  exit(0);

if(get_kb_item("xiongmai/net_surveillance/" + port + "/auth_bypass_possible")) {
  vulnUrl = http_report_vuln_url(port: port, url: "/DVR.htm", url_only: TRUE);
  report = 'It was possible to bypass authentication and view the camera feed through the following URL:\n' + vulnUrl;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
