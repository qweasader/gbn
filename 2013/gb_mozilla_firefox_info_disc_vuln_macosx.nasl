###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Information Disclosure Vulnerability (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804015");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-1729");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-09-24 16:13:31 +0530 (Tue, 24 Sep 2013)");
  script_name("Mozilla Firefox Information Disclosure Vulnerability (Mac OS X)");


  script_tag(name:"summary", value:"Mozilla Firefox is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 24.0 or later.");
  script_tag(name:"insight", value:"Flaw is due to an error within the NVIDIA OS X graphics driver.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 24.0 on Mac OS X, When NVIDIA graphics
drivers used.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain desktop screenshot
data by reading from a CANVAS element.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62474");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-86.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}


include("ssh_func.inc");
include("host_details.inc");
include("version_func.inc");

## Create Socket
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

gpu = chomp(ssh_cmd(socket:sock, cmd:"system_profiler SPDisplaysDataType"));

close(sock);

if("Graphics" >< gpu && "NVIDIA" >< gpu)
{
  if(!ffVer = get_app_version(cpe:CPE)){
    exit(0);
  }

  if(version_is_less(version:ffVer, test_version:"24.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
