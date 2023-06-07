##############################################################################
# OpenVAS Vulnerability Test
#
# Golden FTP Server 'DELE' Command Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801073");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4194");
  script_name("Golden FTP Server 'DELE' Command Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37527");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54497");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10258");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_golden_ftp_server_detect.nasl");
  script_mandatory_keys("Golden/FTP/Free_or_Pro/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow the remote authenticated user
  to access arbitrary folders and delete arbitrary files from the FTP directories.");

  script_tag(name:"affected", value:"Golden FTP Server Pro version 4.30 and prior.
  Golden FTP Server Free version 4.30 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in 'DELE' command.
  It is possible to escape the FTP root and delete arbitrary files on the system
  via directory traversal (../../) attack methods.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Golden FTP Server is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

if(gftpVer = get_kb_item("Golden/FTP/Pro/Ver"))
{
  # Golden FTP server Pro v4.30 = v4.50
  if(version_is_less_equal(version:gftpVer, test_version:"4.50")){
    security_message(port:0);
  }
}

else if(gfftpVer = get_kb_item("Golden/FTP/Free/Ver"))
{
  # Golden FTP server Free v4.30 = v4.50
  if(version_is_less_equal(version:gfftpVer, test_version:"4.50")){
    security_message(port:0);
  }
}