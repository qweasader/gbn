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
  script_oid("1.3.6.1.4.1.25623.1.0.900125");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-4110");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft SQL Server 2000 sqlvdir.dll ActiveX Buffer Overflow Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/496232");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln31129.html");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to a buffer-overflow vulnerability.");

  script_tag(name:"insight", value:"Applications sqlvdir.dll ActiveX control is prone to a buffer-overflow
  vulnerability because it fails to bounds-check user-supplied data before copying it into an insufficiently
  sized buffer. The issue occurs when excessive amounts of data to the Control() method is passed.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2000 SP4 and prior on Microsoft Windows (all).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code and failed attepts causes denial-of-service conditions.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000";
if(!registry_key_exists(key:key)){
  exit(0);
}

msSqlVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!msSqlVer) exit(0);

if(egrep(pattern:"^([0-7]\..*|8\.(0?0(\.([0-9]?[0-9]|1[0-8][0-9]|19[0-4]))?))$", string:msSqlVer)){
  report = report_fixed_ver(installed_version:msSqlVer, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
