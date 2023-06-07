###############################################################################
# OpenVAS Vulnerability Test
#
# ICQ 'ICQToolBar.dll' Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800808");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1915");
  script_name("ICQ 'ICQToolBar.dll' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35150");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50858");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_icq_detect.nasl");
  script_mandatory_keys("ICQ/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"An attacker may leverage this issue by execute arbitrary code
and buffer overflow in the context of affected system, and can cause the
application to crash (persistent).");
  script_tag(name:"affected", value:"ICQ version 6.5 on Windows");
  script_tag(name:"insight", value:"Error due to improper bounds checking by the ICQToolBar.dll and
this can be caused via an Internet shortcut .URL file containing a long
URL parameter, when browsing a folder that contains this file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"ICQ is prone to a stack-based buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

icqVer = get_kb_item("ICQ/Ver");
if(!icqVer){
  exit(0);
}

if(version_is_equal(version:icqVer, test_version:"6.5.0.1042"))
{
  # To Get the Installed Location
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\Uninstall\ICQToolbar", item:"DisplayIcon");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:dllPath - "\icq6Toolbar.ico" + "\ICQToolBar.dll");
  dllVer = GetVer(share:share, file:file);

  if(version_is_less_equal(version:dllVer, test_version:"3.0.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
