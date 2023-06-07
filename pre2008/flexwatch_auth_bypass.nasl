# OpenVAS Vulnerability Test
# Description: FlexWATCH Authentication Bypassing
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# From: "Rafel Ivgi, The-Insider" <theinsider@012.net.il>
# Subject: FlexWATCH-Webs 2.2 (NTSC) Authorization Bypass
# Date: 2004-02-24 16:45

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12078");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8942");
  script_xref(name:"OSVDB", value:"2842");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FlexWATCH Authentication Bypassing");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"There is a vulnerability in the current version of FlexWATCH that allows an
  attacker to access administrative sections without being required to authenticate.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain the list of user accounts on this system
  and the ability to reconfigure this service.

  This is done by adding an additional '/' at the beginning of the URL.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

req = http_get(item:"//admin/aindex.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
find = string("GoAhead-Webs");
find2 = string("admin.htm");
find3 = string("videocfg.htm");
if ( find >< res && find2 >< res && find3 >< res )
{
  security_message(port);
  exit(0);
}

