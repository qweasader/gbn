###############################################################################
# OpenVAS Vulnerability Test
#
# Pidgin MSN and XMPP Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802906");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-2318", "CVE-2012-2214");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-07-04 16:00:59 +0530 (Wed, 04 Jul 2012)");
  script_name("Pidgin MSN and XMPP Denial of Service Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49036/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53706");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=63");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=62");
  script_xref(name:"URL", value:"http://hg.pidgin.im/pidgin/main/rev/4d6bcb4f4ea4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash the affected
  application.");
  script_tag(name:"affected", value:"Pidgin version prior 2.10.4 on Windows");
  script_tag(name:"insight", value:"- An error in 'msn_message_parse_payload()' function handling messages with
    certain characters or character encodings can be exploited to cause a
    crash.

  - An error in SOCKS5 proxy handling code can be exploited to dereference an
    invalid pointer and cause a crash by sending multiple specially crafted
    file transfer requests.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.4 or later.");
  script_tag(name:"summary", value:"This host has installed with Pidgin and is prone to denial of
  service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.4")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.10.4");
    security_message(port:0, data:report);
  }
}
