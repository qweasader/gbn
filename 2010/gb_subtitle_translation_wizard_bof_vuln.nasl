###############################################################################
# OpenVAS Vulnerability Test
#
# Subtitle Translation Wizard '.srt' File Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801426");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-2440");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Subtitle Translation Wizard '.srt' File Stack Based Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40303");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41026");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13965/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to a boundary error when processing subtitle
files in 'st-wizard.exe', which causes a stack-based buffer overflow via '.srt'
file containing an overly long string.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Subtitle Translation Wizard is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code. Failed exploit attempts will result in denial-of-service
conditions.");
  script_tag(name:"affected", value:"Subtitle Translation Wizard 3.0");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Subtitle Translation Wizard_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

stwName = registry_get_sz(key:key, item:"DisplayName");
if("Subtitle Translation Wizard" >< stwName)
{
  stwVer = eregmatch(pattern:"Subtitle Translation Wizard ([0-9.]+)" , string:stwName);
  if(stwVer[1] != NULL)
  {
    if(version_is_equal(version:stwVer[1], test_version:"3.0")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
