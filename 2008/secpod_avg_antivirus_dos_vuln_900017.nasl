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
  script_oid("1.3.6.1.4.1.25623.1.0.900017");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3373");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("AVG Anti-Virus UPX Processing DoS Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.grisoft.com/ww.94247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30417");

  script_tag(name:"summary", value:"AVG AntiVirus is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"The flaw is caused to a divide by zero error in file parsing
  engine while handling UPX compressed executables.");

  script_tag(name:"affected", value:"AVG Anti-Virus prior to 8.0.156.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 8.0.156 or later.");

  script_tag(name:"impact", value:"Remote attackers with successful exploitation could deny the
  service by causing the scanning engine to crash.");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\AVG"))
  exit(0);

for(i = 1; i <= 8; i++) {
  avgVer = registry_get_sz(key:"SOFTWARE\AVG\AVG" + i + "\LinkScanner\Prevalence", item:"CODEVER");
  if(avgVer) {
    # nb: version < 8.0.156
    if(egrep(pattern:"^([0-7]\..*|8\.0(\.([0-9]?[0-9]|1[0-4][0-9]|15[0-5])))$", string:avgVer)) {
      security_message(port:0, data:"The target host was found to be vulnerable");
      exit(0);
    }
    exit(99);
  }
}

exit(99);