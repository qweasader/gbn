# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900158");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-21 15:08:20 +0200 (Tue, 21 Oct 2008)");
  script_cve_id("CVE-2008-5626");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("XM Easy Personal FTP Server 'NSLT' Command Remote DoS Vulnerability");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31739");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/xm_easy_personal/detected");

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service to legitimate users.");

  script_tag(name:"affected", value:"dxmsoft XM Easy Personal FTP Server version 5.6.0 and prior on Windows (all).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"XM Easy Personal FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The vulnerability is due to an error when handling a malformed NLST command.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(!banner || "DXM's FTP Server" >!< banner)
  exit(0);

if(egrep(pattern:"DXM's FTP Server 5\.([0-5](\..*)?|6\.0)($|[^.0-9])", string:banner)) {
  security_message(port:port);
  exit(0);
}
