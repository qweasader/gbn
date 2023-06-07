###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities -01 Apr13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803466");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0793", "CVE-2013-0795",
                "CVE-2013-0797", "CVE-2013-0799", "CVE-2013-0800");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-04-08 14:14:23 +0530 (Mon, 08 Apr 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities -01 Apr13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58836");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58837");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=825721");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 17.x before 17.0.5 on Mac OS X");
  script_tag(name:"insight", value:"- Unspecified vulnerabilities in the browser engine

  - Buffer overflow in the Mozilla Maintenance Service

  - Untrusted search path vulnerability while handling dll files

  - Improper validation of address bar during history navigation

  - Integer signedness error in the 'pixman_fill_sse2' function in
    'pixman-sse2.c' in Pixman

  - Error in 'CERT_DecodeCertPackage' function in Mozilla Network Security
    Services (NSS)

  - The System Only Wrapper (SOW) implementation does not prevent use of the
    cloneNode method for cloning a protected node");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 17.0.5 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");

if(ffVer && ffVer =~ "^(17.0)")
{
  if(version_in_range(version:ffVer, test_version:"17.0", test_version2:"17.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
