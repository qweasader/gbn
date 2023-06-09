###############################################################################
# OpenVAS Vulnerability Test
#
# Kaspersky Internet Security Multiple DOS Vulnerabilities (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107094");
  script_version("2021-10-13T13:01:32+0000");
  script_tag(name:"last_modification", value:"2021-10-13 13:01:32 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-22 13:17:56 +0100 (Tue, 22 Nov 2016)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_cve_id("CVE-2016-4304", "CVE-2016-4305", "CVE-2016-4307");

  script_name("Kaspersky Internet Security Multiple DOS Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://blog.talosintel.com/2016/08/vulnerability-spotlight-multiple-dos.html");
  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_2");
  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_1");

  script_tag(name:"qod", value:"30");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/IntNetSec/Ver");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to cause a local denial of service attacks on any machine running Kaspersky Internet Security software.");
  script_tag(name:"affected", value:"Kaspersky Internet Security 16.0.0.");
  script_tag(name:"insight", value:"This flaw occurs due to a specially crafted native API call which can cause an access violation in KLIF kernel driver.");
  script_tag(name:"solution", value:"Apply the patch from the advisory.");
  script_tag(name:"summary", value:"Kaspersky Internet Security 16.0.0 is prone to multiple DOS vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:kaspersky:kaspersky_total_security";

include("host_details.inc");
include("version_func.inc");

if(!kisVer = get_app_version(cpe:CPE)) exit(0);

if(version_is_equal(version:kisVer, test_version:"16.0.0"))
{
  report = report_fixed_ver(installed_version:kisVer, fixed_version:"See references");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
