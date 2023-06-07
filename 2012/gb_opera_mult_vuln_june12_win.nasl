###############################################################################
# OpenVAS Vulnerability Test
#
# Opera Multiple Vulnerabilities - June12 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802646");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-3555", "CVE-2012-3556", "CVE-2012-3557", "CVE-2012-3558",
                "CVE-2012-3560");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-06-21 15:15:15 +0530 (Thu, 21 Jun 2012)");
  script_name("Opera Multiple Vulnerabilities - June12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49533/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54011");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1018/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1019/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1020/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1021/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1022/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1200/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  script code, disclose sensitive information or spoof the originating URL
  of a trusted web site and carry out phishing-style attacks.");
  script_tag(name:"affected", value:"Opera version prior to 11.65 on Windows");
  script_tag(name:"insight", value:"- An error when displaying preferences within a small window can be exploited
    to execute arbitrary code by tricking a user into entering a specific
    keyboard sequence.

  - An error when displaying pop-up windows can be exploited to execute script
    code by tricking a user into following a specific sequence of events.

  - An error when handling JSON resources can be exploited to bypass the cross
    domain policy restriction and disclose certain information to other sites.

  - An unspecified error can be exploited to display arbitrary content while
    showing the URL of a trusted web site in the address bar.

  - An error when handling page loads can be exploited to display arbitrary
    content while showing the URL of a trusted web site in the address.");
  script_tag(name:"solution", value:"Upgrade to Opera version 11.65 or 12 or later.");
  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.65")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.65");
  security_message(port:0, data:report);
}
