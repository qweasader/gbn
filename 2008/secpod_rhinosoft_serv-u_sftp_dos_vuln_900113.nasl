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
  script_oid("1.3.6.1.4.1.25623.1.0.900113");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3731");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("RhinoSoft Serv-U SFTP Remote Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30739");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31461/");
  script_dependencies("secpod_servu_ftp_server_detect.nasl");
  script_mandatory_keys("Serv-U/FTPServ/Ver");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 7.2.0.1.");

  script_tag(name:"summary", value:"RhinoSoft Serv-U SFTP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an error within the logging functionality, when
  creating directories via SFTP or when handling certain SFTP commands.");

  script_tag(name:"affected", value:"RhinoSoft Serv-U versions prior to 7.2.0.1 on Windows (All).");

  script_tag(name:"impact", value:"Remote exploitation will allow attackers to cause the server crash
  or denying the service.");

  exit(0);
}

servuVer = get_kb_item("Serv-U/FTPServ/Ver");
if(!servuVer){
  exit(0);
}

if(egrep(pattern:"^([0-6]\..*|7\.([01](\..*)?|2(\.0(\.1)?)?))$", string:servuVer)){
  security_message(port:0);
}