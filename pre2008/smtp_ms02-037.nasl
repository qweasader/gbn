# OpenVAS Vulnerability Test
# Description: IMC SMTP EHLO Buffer Overrun
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11053");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0698");
  script_name("IMC SMTP EHLO Buffer Overrun");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("SMTP problems");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5306");

  script_tag(name:"solution", value:"The vendor has released updates. Please see thee references
  for more information.");

  script_tag(name:"summary", value:"A security vulnerability results because of an unchecked buffer
  in the IMC code that generates the response to the EHLO protocol command.");

  script_tag(name:"impact", value:"If the buffer were overrun with data it would result in either the
  failure of the IMC or could allow the attacker to run code in the security context of the IMC,
  which runs as Exchange5.5 Service Account.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

banner = smtp_get_banner(port:port);
if(!banner || !egrep(pattern:"^220.*Microsoft Exchange Internet.*", string:banner))
  exit(0);

# needs to be 5.5.2656.59 or GREATER.

#this good:
#220 proliant.fdma.com ESMTP Server (Microsoft Exchange Internet Mail Service 5.5.2656.59) ready

#this old:
#220 proliant.fdma.com ESMTP Server (Microsoft Exchange Internet Mail Service 5.5.2653.13) ready

if(egrep(string:banner, pattern:"Service.5\.[6-9]"))
  exit(99);

if(egrep(string:banner, pattern:"Service.5\.5\.[3-9]"))
  exit(99);

if(egrep(string:banner, pattern:"Service.5\.5\.2[7-9]"))
  exit(99);

if(egrep(string:banner, pattern:"Service.5\.5\.26[6-9]"))
  exit(99);

if(egrep(string:banner, pattern:"Service.5\.5\.265[6-9]"))
  exit(99);

security_message(port:port);
