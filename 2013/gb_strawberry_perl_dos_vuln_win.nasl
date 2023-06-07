###############################################################################
# OpenVAS Vulnerability Test
#
# Strawberry Perl Denial of Service Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service
  (memory consumption) via specially-crafted hash key.");
  script_tag(name:"affected", value:"Strawberry Perl versions 5.8.2 before 5.14.4 and 5.15 before 5.16.3 on Windows");
  script_tag(name:"insight", value:"Flaw is due to an error when rehashing user-supplied input.");
  script_tag(name:"solution", value:"Upgrade to Strawberry Perl version 5.16.3 or 5.14.4 or later.");
  script_tag(name:"summary", value:"Strawberry Perl is prone to a denial of service (DoS) vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803371");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-1667");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-04-09 18:21:13 +0530 (Tue, 09 Apr 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Strawberry Perl Denial of Service Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52472");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58311");
  script_xref(name:"URL", value:"http://perlnews.org/2013/03/rehashing-flaw");
  script_xref(name:"URL", value:"http://perlnews.org/2013/03/perl-5-16-3-and-5-14-4-just-released");
  script_xref(name:"URL", value:"http://www.nntp.perl.org/group/perl.perl5.porters/2013/03/msg199755.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
  script_xref(name:"URL", value:"http://strawberryperl.com");
  exit(0);
}


include("version_func.inc");

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer && spVer =~ "^5\.")
{
  if(version_in_range(version:spVer, test_version:"5.8.2", test_version2:"5.14.3")||
     version_in_range(version:spVer, test_version:"5.15", test_version2:"5.16.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
