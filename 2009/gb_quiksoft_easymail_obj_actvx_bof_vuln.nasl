###############################################################################
# OpenVAS Vulnerability Test
#
# QuikSoft EasyMail Objects ActiveX Control BOF Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800535");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6447");
  script_name("QuikSoft EasyMail Objects ActiveX Control BOF Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32722");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47207");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Attackers may exploit this issue by executing arbitrary code in the context
  of a Web page and can cause buffer overflow.");
  script_tag(name:"affected", value:"QuikSoft EasyMail MailStore with emmailstore.dll version 6.5.0.3 on Windows");
  script_tag(name:"insight", value:"Flaw exists in CreateStore method in emmailstore.dll file, which fails to
  perform adequate boundary checks on user-supplied data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"QuikSoft EasyMail Objects ActiveX Control is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.quiksoft.com/");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Quiksoft\EasyMail Objects")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  emoName = registry_get_sz(key:key + item, item:"DisplayName");
  if("EasyMail Objects" >< emoName)
  {
    dllPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(dllPath != NULL)
    {
      dllPath = dllPath + "emmailstore.dll";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

      dllVer = GetVer(file:file, share:share);
      if(version_is_less_equal(version:dllVer, test_version:"6.5.0.3")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
    exit(0);
  }
}
