###############################################################################
# OpenVAS Vulnerability Test
#
# InduSoft Web Studio Multiple Remote Code Execution Vulnerabilitites
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802537");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-4051", "CVE-2011-4052");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-07 17:02:41 +0530 (Wed, 07 Dec 2011)");
  script_name("InduSoft Web Studio Multiple Remote Code Execution Vulnerabilitites");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"insight", value:"The flaws are due to

  - An error in 'CEServer component'. When handling the remove File operation
  (0x15) the process blindly copies user supplied data to a fixed-length buffer on the stack.

  - An error in remote agent component (CEServer.exe). When handling incoming
  requests the process fails to perform any type of authentication, which
  allows direct manipulation and creation of files on disk, loading of
  arbitrary DLLs and process control.");

  script_tag(name:"summary", value:"Indusoft Web Studio is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"solution", value:"Install the hotfix.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the affected application.");

  script_tag(name:"affected", value:"InduSoft Web Studio version 6.1 and 7.0.");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-329/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50677");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-330/");
  script_xref(name:"URL", value:"http://www.indusoft.com/hotfixes/hotfixes.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\InduSoft Ltd."))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key))
{
  indName = registry_get_sz(key:key + item, item:"DisplayName");

  if("InduSoft Web Studio" >< indName)
  {
    indVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!indVer){
      exit(0);
    }

    indVer = eregmatch(pattern:"v?([0-9.]+)", string:indVer);
    if(indVer[1])
    {
      if(version_is_equal(version:indVer[1], test_version:"6.1") ||
         version_is_equal(version:indVer[1], test_version:"7.0"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
