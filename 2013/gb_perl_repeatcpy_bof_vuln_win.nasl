# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803161");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-5195");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-23 19:28:09 +0530 (Wed, 23 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Strawberry Perl 'Perl_repeatcpy()' Function Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51457");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56287");
  script_xref(name:"URL", value:"http://www.nntp.perl.org/group/perl.perl5.porters/2012/10/msg193886.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
  (memory consumption and crash) or possibly execute arbitrary code via the
  'x' string repeat operator.");
  script_tag(name:"affected", value:"Strawberry Perl 5.12.x before 5.12.5, 5.14.x before 5.14.3 and
  5.15.x before 15.15.5 on Windows");
  script_tag(name:"insight", value:"The Perl_repeatcpy() function in util.c fails to properly sanitize user
  supplied input while handling the string repeat operator.");
  script_tag(name:"solution", value:"Upgrade to Strawberry Perl 5.12.5, 5.14.3, 15.15.5 or later.");
  script_tag(name:"summary", value:"Strawberry Perl is prone to heap based buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://strawberryperl.com");
  exit(0);
}


include("version_func.inc");

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer && spVer =~ "^(5\.(12|14|15))")
{
  if(version_in_range(version:spVer, test_version:"5.12.0", test_version2:"5.12.4") ||
     version_in_range(version:spVer, test_version:"5.14.0", test_version2:"5.14.2") ||
     version_in_range(version:spVer, test_version:"5.15.0", test_version2:"5.15.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
