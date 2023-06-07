# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902527");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-1753");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ejabberd XML Parsing Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48072");
  script_xref(name:"URL", value:"http://www.ejabberd.im/ejabberd-2.1.7");
  script_xref(name:"URL", value:"http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.7/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_ejabberd_detect_win.nasl");
  script_mandatory_keys("ejabberd/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a denial of service.");
  script_tag(name:"affected", value:"ejabberd versions before 2.1.7 and 3.x before 3.0.0-alpha-3");
  script_tag(name:"insight", value:"The flaw is due to an error within the parsing of certain XML input,
  which can be exploited to cause a high CPU and memory consumption via a
  crafted XML document containing a large number of nested entity references.");
  script_tag(name:"solution", value:"Upgrade to ejabberd version 2.1.7, 3.0.0-alpha-3 or later.");
  script_tag(name:"summary", value:"ejabberd is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("ejabberd/Win/Ver");
if(ver)
{
  ver = ereg_replace(pattern:"-", replace:".", string:ver);

  if(version_is_less(version:ver, test_version:"2.1.7") ||
     version_in_range(version:ver, test_version:"3.0.0", test_version2:"3.0.0.alpha.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
