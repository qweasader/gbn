###############################################################################
# OpenVAS Vulnerability Test
#
# NJStar Communicator MiniSMTP Server Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802266");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-4040");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-08 19:46:14 +0530 (Tue, 08 Nov 2011)");
  script_name("NJStar Communicator MiniSMTP Server Remote Stack Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"NJStar Communicator Version 3.00.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the MiniSmtp server when
  processing packets. This can be exploited to cause a stack-based buffer overflow via a specially crafted
  packet sent to TCP port 25.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NJStar Communicator MiniSMTP Server is prone to a buffer overflow vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50452");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18057");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);

help = get_kb_item("smtp/fingerprints/" + port + "/help_banner");
if(!help || "E-mail Server From NJStar Software" >!< help)
  exit(0);

if(!soc = smtp_open(port:port))
  exit(0);

send(socket:soc, data:crap(512));
smtp_close(socket:soc, check_data:FALSE);

if(!soc = smtp_open(port:port)){
  security_message(port:port);
  exit(0);
}

smtp_close(socket:soc, check_data:FALSE);
