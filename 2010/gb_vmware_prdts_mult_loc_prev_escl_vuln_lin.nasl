###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Multiple Local Privilege Escalation Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801559");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4295", "CVE-2010-4296");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Multiple Local Privilege Escalation Vulnerabilities (VMSA-2010-0018) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42453/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45168");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2010-0018.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code with elevated privileges, this may aid in other attacks.");

  script_tag(name:"affected", value:"VMware Server version 2.x

  VMware Player 3.x before 3.1.2 build 301548

  VMware Workstation 7.x before 7.1.2 build 301548");

  script_tag(name:"insight", value:"The flaws are due to:

  - Race conditions within the 'vmware-mount' utility when handling temporary files during the
  mounting process can be exploited to create files or directories.

  - An error within the 'vmware-mount' utility when loading libraries that can be exploited to
  execute arbitrary code with root privileges.");

  script_tag(name:"summary", value:"VMware products are prone to multiple local privilege escalation
  vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("version_func.inc");

if(!get_kb_item("VMware/Linux/Installed"))
  exit(0);

vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
