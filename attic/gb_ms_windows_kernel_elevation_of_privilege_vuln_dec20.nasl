# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817567");
  script_version("2021-11-09T08:41:29+0000");
  script_cve_id("CVE-2020-17008");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-11-09 08:41:29 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-01-12 15:51:17 +0530 (Tue, 12 Jan 2021)");
  script_name("Microsoft Windows Kernel Elevation of Privilege Vulnerability (CVE-2020-17008)");

  script_tag(name:"summary", value:"Microsoft Windows is prone to an elevation of privilege
  vulnerability.

  This VT has been replaced by the following VTs covering the new CVE-2021-1648:

  - OID: 1.3.6.1.4.1.25623.1.0.817573

  - OID: 1.3.6.1.4.1.25623.1.0.817569

  - OID: 1.3.6.1.4.1.25623.1.0.817568");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to wrong fix of pointers which are simply
  changed to offsets.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to elevate
  privilges.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 10 Version 1803

  - Microsoft Windows 10

  - Microsoft Windows 10 Version 1607

  - Microsoft Windows 10 Version 1709

  - Microsoft Windows 10 Version 1809

  - Microsoft Windows 10 Version 1903

  - Microsoft Windows 10 Version 1909

  - Microsoft Windows 10 Version 2004

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2016

  - Microsoft Windows Server 2019");

  script_tag(name:"solution", value:"The vendor has released updates Please check the referenced
  replacement VTs for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);