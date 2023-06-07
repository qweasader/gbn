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
  script_oid("1.3.6.1.4.1.25623.1.0.900010");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28485");
  script_cve_id("CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Wireshark Multiple Vulnerabilities - July08 (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"insight", value:"The flaws exist due to errors in GSM SMS dissector, PANA and KISMET
  dissectors, RTMPT dissector, RMI dissector, and in syslog dissector.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to wireshark to 1.0.1 or later.

  Quick Fix : Disable the following dissectors: GSM SMS, PANA, KISMET, RTMPT, and RMI");

  script_tag(name:"summary", value:"Wireshark/Ethereal is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Wireshark versions prior to 1.0.1 on Windows (All).");

  script_tag(name:"impact", value:"Successful exploitation could result in application crash,
  disclose of system memory, and an incomplete syslog encapsulated packets.");

  exit(0);
}

include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 etherealVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                   "\Uninstall\Ethereal", item:"DisplayVersion");
 if(etherealVer)
 {
    etherealVer = ereg_replace(pattern:"Ethereal (.*)", replace:"\1",
                                   string:etherealVer);
    if(ereg(pattern:"^(0\.(10\.([0-9]|1[0-4])|99\.0))$",
        string:etherealVer))
    {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
    }
 }

 wiresharkVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                    "\Uninstall\Wireshark", item:"DisplayVersion");
 if(!wiresharkVer){
    exit(0);
 }

 if(ereg(pattern:"^(0\.99\.[0-9]|1\.0\.0)$", string:wiresharkVer)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
 }
