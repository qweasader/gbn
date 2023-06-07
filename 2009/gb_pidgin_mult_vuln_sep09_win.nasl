###############################################################################
# OpenVAS Vulnerability Test
#
# Pidgin Multiple Vulnerabilities - Sep09 (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800931");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3025", "CVE-2009-3026");
  script_name("Pidgin Multiple Vulnerabilities - Sep09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36384/");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=35");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=542891");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/08/19/2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker obtain sensitive information
  by sniffing XMPP sessions and cause application crash.");
  script_tag(name:"affected", value:"Pidgin version 2.6.0 on Windows");
  script_tag(name:"insight", value:"- The application connects to Jabberd servers that are not fully compliant
   with the XMPP specifications without encryption, even if the
   'Require SSL/TLS' setting is configured.

  - An error occurs in compililg libpurple while processing malicious links
   received via the Yahoo Messenger protocol.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.6.1.");
  script_tag(name:"summary", value:"Pidgin is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(!pidginVer)
  exit(0);

if(version_is_equal(version:pidginVer, test_version:"2.6.0")){
  report = report_fixed_ver(installed_version:pidginVer, vulnerable_range:"Equal to 2.6.0");
  security_message(port: 0, data: report);
}
