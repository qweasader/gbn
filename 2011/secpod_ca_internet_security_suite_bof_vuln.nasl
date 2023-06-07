# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901177");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_cve_id("CVE-2010-4502");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CA Internet Security Suite Plus 'KmxSbx.sys' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42267");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15624");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024808");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3070");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to an error in the 'KmxSbx.sys' kernel driver
when processing IOCTLs and can be exploited to cause a buffer overflow via
overly large data buffer sent to the 0x88000080 IOCTL.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"CA Internet Security Suite Plus is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code in the
kernel.");
  script_tag(name:"affected", value:"CA Internet Security Suite Plus 2010");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ComputerAssociates")){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysPath = sysPath + "\system32\drivers\KmxSbx.sys";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath);

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(version_is_equal(version:sysVer, test_version:"6.2.0.22")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
