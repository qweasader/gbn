# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902313");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3202");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Flock Browser Malformed Bookmark Cross site scripting Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flock_detect_win.nasl");
  script_mandatory_keys("Flock/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute HTML code in the
  context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials.");
  script_tag(name:"affected", value:"Flock versions 3.0 to 3.0.0.4093");
  script_tag(name:"insight", value:"The flaw is due to malformed favourite imported from an HTML file,
  imported from another browser, or manually created can bypass cross-origin
  protection, which has unspecified impact and attack vectors.");
  script_tag(name:"solution", value:"Upgrade to the Flock version 3.0.0.4094");
  script_tag(name:"summary", value:"Flock browser is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://flock.com/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42556");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2010/08/flock-browser-3003989-malformed.html");
  script_xref(name:"URL", value:"http://www.flock.com/");
  exit(0);
}


include("version_func.inc");

flockVer = get_kb_item("Flock/Win/Ver");
if(!flockVer){
  exit(0);
}

if(version_in_range(version:flockVer, test_version:"3.0", test_version2:"3.0.0.4093")){
  report = report_fixed_ver(installed_version:flockVer, vulnerable_range:"3.0 - 3.0.0.4093");
  security_message(port: 0, data: report);
}
