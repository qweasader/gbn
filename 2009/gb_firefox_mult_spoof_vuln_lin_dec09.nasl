###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Spoofing Vulnerabilities - dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801094");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-4129", "CVE-2009-4130");
  script_name("Mozilla Firefox Multiple Spoofing Vulnerabilities (Dec 2009) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54612");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37232");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54611");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Dec/1023287.html");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple spoofing vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A race condition error allows attackers to produce a JavaScript message with a spoofed domain
  association by writing the message in between the document request and document load for a web
  page in a different domain.

  - Visual truncation vulnerability in the MakeScriptDialogTitle function in nsGlobalWindow.cpp in
  Mozilla Firefox allows remote attackers to spoof the origin domain name of a script via a long
  name.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct spoofing
  attacks and possibly launch further attacks on the system.");

  script_tag(name:"affected", value:"Mozilla Firefox version 3.0 through 3.5.5.");

  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Linux/Ver");
if(!vers)
  exit(0);

if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.5.5")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"3.0 - 3.5.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
