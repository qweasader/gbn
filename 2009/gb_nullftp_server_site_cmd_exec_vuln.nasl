###############################################################################
# OpenVAS Vulnerability Test
#
# Null FTP Server SITE Command Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800546");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6534");
  script_name("Null FTP Server SITE Command Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32656");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7355");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47099");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_nullftp_server_detect.nasl");
  script_mandatory_keys("NullFTP/Server/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary codes
  in the context of the application.");

  script_tag(name:"affected", value:"NULL FTP Server Free and Pro version prior to 1.1.0.8 on Windows");
  script_tag(name:"insight", value:"An error is generated while handling custom SITE command containing shell
  metacharacters such as & (ampersand) as a part of an argument.");

  script_tag(name:"solution", value:"Upgrade to the latest version 1.1.0.8 or later.");

  script_tag(name:"summary", value:"Null FTP Server is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("NullFTP/Server/Ver");
if(!ver)
  exit(0);

if(version_is_less(version:ver, test_version:"1.1.0.8")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"1.1.0.8");
  security_message(port: 0, data: report);
}
