##############################################################################
# OpenVAS Vulnerability Test
#
# NETGEAR WNR1000 'Image' Request Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803188");
  script_version("2022-03-03T10:23:45+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-03 10:23:45 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2013-04-05 18:28:47 +0530 (Fri, 05 Apr 2013)");
  script_name("NETGEAR WNR1000 'Image' Request Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Apr/5");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24916");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121025");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WNR1000/banner");

  script_tag(name:"insight", value:"The web server skipping authentication for certain requests that contain
  a '.jpg' substring. With a specially crafted URL, a remote attacker can
  bypass authentication and gain access to the device configuration.");

  script_tag(name:"solution", value:"Upgrade to NETGEAR with firmware version 1.0.2.60 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"NETGEAR WNR1000 is prone to an authentication bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain administrative access,
  circumventing existing authentication mechanisms.");

  script_tag(name:"affected", value:"NETGEAR WNR1000v3 firmware version prior to 1.0.2.60");

  script_xref(name:"URL", value:"http://www.netgear.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if("NETGEAR WNR1000" >!< banner){
  exit(0);
}

if(http_vuln_check(port:port, url:"/NETGEAR_fwpt.cfg?.jpg",
   pattern:"Content-type: application/configuration",
   check_header:TRUE, extra_check:"Content-length:"))
{
  security_message(port:port);
  exit(0);
}

exit(99);
