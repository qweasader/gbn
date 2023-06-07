###############################################################################
# OpenVAS Vulnerability Test
#
# ArGoSoft FTP Server .NET Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100539");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-17 13:20:23 +0100 (Wed, 17 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("ArGoSoft FTP Server .NET Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38756");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/argosoft/ftp/detected");

  script_tag(name:"summary", value:"ArGoSoft FTP Server .NET is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to upload and download
  arbitrary files outside of the FTP server root directory. This could help the attacker launch further attacks.");

  script_tag(name:"affected", value:"ArGoSoft FTP Server .NET 1.0.2.1 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

ftpPort = ftp_get_port(default:21);

banner = ftp_get_banner(port: ftpPort);
if(!banner || "ArGoSoft" >!< banner)
  exit(0);

version = eregmatch(pattern: "v.([0-9.]+)", string:banner);
if(isnull(version[1]))
  exit(0);

if(version_is_equal(version: version[1], test_version: "1.0.2.1")) {
  security_message(port: ftpPort);
  exit(0);
}

exit(99);
