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
  script_oid("1.3.6.1.4.1.25623.1.0.900663");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1373", "CVE-2009-1374",
                "CVE-2009-1375", "CVE-2009-1376");
  script_name("Pidgin Multiple Buffer Overflow Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35067");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35202");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50680");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1059.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_pidgin_detect_lin.nasl");
  script_mandatory_keys("Pidgin/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploits allow attackers to run arbitrary code, corrupt memory
  and cause cause denial of service.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.5.6 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - a boundary error in the XMPP SOCKS5 'bytestream' server when initiating
    an outbound XMPP file transfer.

  - a boundary error in the 'decrypt_out()' function while processing
    malicious QQ packet.

  - a boundary error exists in the implementation of the 'PurpleCircBuffer'
    structure and can be exploited via vectors involving  XMPP or Sametime
    protocol.

  - a truncation error in  function 'libpurple/protocols/msn/slplink.c' and
   'libpurple/protocols/msnp9/slplink.c' when processing MSN SLP messages
    with a crafted offset value.");
  script_tag(name:"solution", value:"Upgrade to version 2.5.6 or later.");
  script_tag(name:"summary", value:"This host has installed pidgin and is prone to Multiple Buffer
  Overflow Vulnerabilities");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Lin/Ver");
if(!pidginVer)
  exit(0);

if(version_is_less(version:pidginVer, test_version:"2.5.6")){
  report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.5.6");
  security_message(port: 0, data: report);
}
