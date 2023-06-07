###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox SOCKS5 Proxy Server DoS Vulnerability Aug-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800858");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2470");
  script_name("Mozilla Firefox SOCKS5 Proxy Server DoS Vulnerability Aug-09 (Linux)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=459524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35925");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-38.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to cause Denial of Service condition
  in an affected proxy server.");

  script_tag(name:"affected", value:"Firefox version before 3.0.12 or 3.5 before 3.5.2 on Linux.");

  script_tag(name:"insight", value:"Error exists when application fails to handle long domain name in a response
  which leads remote 'SOCKS5' proxy servers into data stream corruption.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.12/3.5.2.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.0.12")||
   version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.1")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
