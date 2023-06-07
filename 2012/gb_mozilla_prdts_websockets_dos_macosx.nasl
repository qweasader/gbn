###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox 'WebSockets' Denial of Service Vulnerability (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802993");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2012-4191");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Firefox 'WebSockets' Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55889");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50935");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code via unspecified vectors.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 16.0.1 on Mac OS X.");

  script_tag(name:"insight", value:"Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 16.0.1 or later.");

  script_tag(name:"summary", value:"Mozilla firefox is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"16.0.1"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"16.0.1");
    security_message(port:0, data:report);
    exit(0);
  }
}