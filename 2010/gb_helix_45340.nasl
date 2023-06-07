###############################################################################
# OpenVAS Vulnerability Test
#
# Helix Server Administration Interface Cross Site Request Forgery Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100945");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-12-14 13:08:24 +0100 (Tue, 14 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Helix Server Administration Interface Cross Site Request Forgery Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45340");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_tag(name:"summary", value:"Helix Server is prone to a cross-site request-forgery vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to perform unauthorized actions by
  enticing a logged-in user to visit a malicious site.");

  script_tag(name:"affected", value:"Helix Server 14.0.1.571 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:554, proto:"rtsp");

if(!server = get_kb_item("RTSP/" + port + "/server_banner"))
  exit(0);

if("Server: Helix" >!< server)
  exit(0);

version = eregmatch(pattern:"Version ([0-9.]+)", string:server);
if(isnull(version[1]))
  exit(0);

if(version_is_equal(version:version[1], test_version:"14.0.1.571")) {
  security_message(port:port);
  exit(0);
}

exit(99);
