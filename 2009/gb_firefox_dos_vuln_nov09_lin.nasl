###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Denial Of Service Vulnerability Nov-09 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801135");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3382");
  script_name("Mozilla Firefox Denial Of Service Vulnerability Nov-09 (Linux)");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=514960");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36866");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-64.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Denial of Service or arbitrary code execution.");
  script_tag(name:"affected", value:"Firefox version 3.0 before 3.0.15 on Linux.");
  script_tag(name:"insight", value:"A memory corruption error in layout/base/nsCSSFrameConstructor.cpp in the
  browser engine can be exploited to potentially execute arbitrary code or
  crash the browser.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.15.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.14")) {
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.0 - 3.0.14");
  security_message(port: 0, data: report);
}
