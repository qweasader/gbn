###############################################################################
# OpenVAS Vulnerability Test
#
# Perl Laundering Security Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801771");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1487");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Perl Laundering Security Bypass Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47124");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66528");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/04/04/35");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security checks in
  perl applications that rely on TAINT mode protection functionality.");
  script_tag(name:"affected", value:"Perl version 5.10.x, 5.11.x, 5.12.x to 5.12.3 and 5.13.x to 5.13.11 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to the 'uc()', 'lc()', 'lcfirst()', and 'ucfist()'
  functions incorrectly laundering tainted data, which can result in the
  unintended use of potentially malicious data after using these functions.");
  script_tag(name:"solution", value:"Upgrade to Perl version 5.14 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Perl is prone to a security bypass vulnerability.");
  exit(0);
}

include("version_func.inc");

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if((apVer =~ "^5\.10") || (apVer =~ "^5\.11") ||
     version_in_range(version:apVer, test_version:"5.12", test_version2:"5.12.3") ||
     version_in_range(version:apVer, test_version:"5.13", test_version2:"5.13.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if((spVer =~ "^5\.10") || (spVer =~ "^5\.11") ||
     version_in_range(version:spVer, test_version:"5.12", test_version2:"5.12.3") ||
     version_in_range(version:spVer, test_version:"5.13", test_version2:"5.13.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
