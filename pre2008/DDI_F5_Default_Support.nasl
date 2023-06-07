# OpenVAS Vulnerability Test
# Description: F5 Device Default Support Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10820");
  script_version("2022-04-11T14:03:55+0000");
  script_tag(name:"last_modification", value:"2022-04-11 14:03:55 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("F5 Device Default Support Password (HTTP)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2001 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Remove the support account entirely or
  change the password of this account to something that is difficult to guess.");

  script_tag(name:"summary", value:"This F5 Networks system still has the default
  password set for the support user account. This account normally provides read/write
  access to the web configuration utility.");

  script_tag(name:"impact", value:"An attacker could take advantage of this to reconfigure
  your systems and possibly gain shell access to the system with super-user privileges.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:443);

req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n\r\n");
buf = http_send_recv(port:port, data:req);

if (("/bigipgui/" >< buf) && ("System Command" >< buf)) {
  security_message(port:port);
}
