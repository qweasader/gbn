###############################################################################
# OpenVAS Vulnerability Test
#
# Pidgin Yahoo Protocol 'YMSG' NULL Pointer Dereference Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801764");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1091");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("Pidgin Yahoo Protocol 'YMSG' NULL Pointer Dereference DoS Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46837");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=51");
  script_xref(name:"URL", value:"http://developer.pidgin.im/viewmtn/revision/info/a7c415abba1f5f01f79295337518837f73d99bb7");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");

  script_tag(name:"summary", value:"Pidgin is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"Pidgin version 2.6.0 through 2.7.10 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to a NULL pointer dereference error when
  processing certain YMSG packets, which can be exploited to crash the process by sending specially
  crafted YMSG packets.");

  script_tag(name:"solution", value:"Update to version 2.7.11 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Pidgin/Win/Ver"))
  exit(0);

if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.7.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.7.11");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
