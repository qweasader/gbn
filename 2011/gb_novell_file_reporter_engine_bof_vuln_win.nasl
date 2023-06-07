###############################################################################
# OpenVAS Vulnerability Test
#
# Novell File Reporter Engine 'RECORD' Processing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801959");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2220");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Novell File Reporter Engine 'RECORD' Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45065");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-227/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/518632/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.");
  script_tag(name:"affected", value:"Novell File Reporter Engine version prior to 1.0.2.53");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the 'NFREngine.exe' when
  parsing certain tags inside a RECORD element. This can be exploited to
  cause a stack-based buffer overflow via specially crafted packets sent
  to TCP port 3035.");
  script_tag(name:"solution", value:"Upgrade Novell File Reporter Engine 1.0.2.53 or later.");
  script_tag(name:"summary", value:"Novell File Reporter engine is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=rCAgCcbPH9s~");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(!registry_key_exists(key:"SOFTWARE\Novell\File Reporter")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  nfrName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Novell File Reporter Engine" >< nfrName)
  {
    nfrVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(nfrVer != NULL)
    {
      if(version_is_less(version:nfrVer, test_version:"1.0.200.53"))
      {
        report = report_fixed_ver(installed_version:nfrVer, fixed_version:"1.0.200.53");
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
