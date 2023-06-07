# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900901");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0192", "CVE-2009-2456", "CVE-2009-2457");
  script_name("Novell eDirectory Multiple Vulnerabilities - Jul09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35666");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1883");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_novell_prdts_detect_lin.nasl");
  script_mandatory_keys("Novell/eDir/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash the service
  leading to denial of service condition.");
  script_tag(name:"affected", value:"Novell eDirectory 8.8 before SP5 on Linux.");
  script_tag(name:"insight", value:"- An unspecified error occurs in DS\NDSD component while processing malformed
    LDAP request containing multiple . (dot) wildcard characters in the Relative
    Distinguished Name (RDN).

  - An unspecified error occurs in DS\NDSD component while processing malformed
    bind LDAP packets.

  - Off-by-one error occurs in the iMonitor component while processing
    malicious HTTP request with a crafted Accept-Language header.");
  script_tag(name:"solution", value:"Upgrade to  Novell eDirectory 8.8 SP5 or later.");
  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

eDirVer = get_kb_item("Novell/eDir/Lin/Ver");
if(!eDirVer)
  exit(0);

if(version_in_range(version:eDirVer, test_version:"8.8", test_version2:"8.8.SP4")){
  report = report_fixed_ver(installed_version:eDirVer, vulnerable_range:"8.8 - 8.8.SP4");
  security_message(port: 0, data: report);
}
