# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900407");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-5256");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Sun xVM VirtualBox Insecure Temporary Files Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32444");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker perform malicious actions
  with the escalated previleges.");

  script_tag(name:"affected", value:"Sun xVM VirutalBox version prior to 2.0.6 versions on all Windows platforms.");

  script_tag(name:"insight", value:"Error is due to insecured handling of temporary files in the 'AcquireDaemonLock'
  function in ipcdUnix.cpp. This allows local users to overwrite arbitrary
  files via a symlink attack on a TMP/.vbox-$USER-ipc/lock temporary file.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version 2.0.6 or above.");

  script_tag(name:"summary", value:"Sun xVM VirtualBox is prone to an 'insecure temporary files' vulnerability.");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

xvm_key  =  registry_get_sz(key:"SOFTWARE\Sun\xVM VirtualBox", item:"Version");
if(xvm_key)
{
  pattern = "^([01](\..*)?|2\.0(\.[0-5])?)$";
    if(egrep(pattern:pattern, string:xvm_key)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
