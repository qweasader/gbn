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
  script_oid("1.3.6.1.4.1.25623.1.0.900018");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3244");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("F-PROT Antivirus Multiple DoS Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.f-prot.com/download/ReleaseNotesWindows.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30253");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30258");

  script_tag(name:"summary", value:"F-PROT Antivirus is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"insight", value:"The issues are due to:

  - input validation error while processing the nb_dir field of
  CHM file's header.

  - improper handling of specially crafted UPX-compressed files,
  Microsoft Office files, and ASPack-compressed files.");

  script_tag(name:"affected", value:"F-Prot Antivirus for Windows prior to 6.0.9.0 on Windows (All).");

  script_tag(name:"solution", value:"Upgrade to latest F-PROT Antivirus or later.");

  script_tag(name:"impact", value:"Remote attackers can easily crash the engine/service via
  specially crafted files.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\FRISK Software\F-PROT Antivirus for Windows")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  fprotName = registry_get_sz(item:"DisplayName", key:key + entry);

  if(fprotName && "F-PROT Antivirus for Windows" >< fprotName) {

    fprotVer = registry_get_sz(item:"DisplayVersion", key:key + entry);

    if(fprotVer && egrep(pattern:"^([0-5]\..*|6\.0\.[0-8](\..*)?)$", string:fprotVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);
