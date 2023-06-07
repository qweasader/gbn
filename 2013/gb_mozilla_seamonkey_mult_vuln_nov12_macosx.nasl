###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Seamonkey Multiple Vulnerabilities - November12 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803634");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities - November12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56306");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027703");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-90.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions.");
  script_tag(name:"affected", value:"Mozilla SeaMonkey version before 2.13.2 on Mac OS X");
  script_tag(name:"insight", value:"Multiple errors

  - When handling the 'window.location' object.

  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal.

  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection.");
  script_tag(name:"solution", value:"Upgrade to Mozilla SeaMonkey version to 2.13.2 or later.");
  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"2.13.2"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.13.2");
    security_message(port: 0, data: report);
    exit(0);
  }
}
