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
  script_oid("1.3.6.1.4.1.25623.1.0.900448");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_cve_id("CVE-2008-5913");
  script_name("Firefox Information Disclosure Vulnerability Jan09 (Windows)");
  script_xref(name:"URL", value:"http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33276");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes in the context of the web browser and can obtain sensitive information
  of the remote user through the web browser.");

  script_tag(name:"affected", value:"Mozilla Firefox version from 2.0 to 3.0.5 on Windows.");

  script_tag(name:"insight", value:"The Web Browser fails to properly enforce the same-origin policy, which leads
  to cross-domain information disclosure.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to an information disclosure vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(!firefoxVer){
  exit(0);
}

if(version_in_range(version:firefoxVer, test_version:"2.0", test_version2:"3.0.5")) {
  report = report_fixed_ver(installed_version:firefoxVer, vulnerable_range:"2.0 - 3.0.5");
  security_message(port: 0, data: report);
}
