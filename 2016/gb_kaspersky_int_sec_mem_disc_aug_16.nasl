###############################################################################
# OpenVAS Vulnerability Test
#
# Kaspersky Internet Security KLDISK Driver Multiple Kernel Memory Disclosure Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.107095");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-11-24 13:17:56 +0100 (Thu, 24 Nov 2016)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_cve_id("CVE-2016-4306");

  script_name("Kaspersky Internet Security <= 16.0.0.614 KLDISK Driver Multiple Kernel Memory Disclosure Vulnerabilities - Windows");

  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0168/");
  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/TotNetSec/Ver");

  script_tag(name:"summary", value:"Kaspersky Internet Security is prone to multiple kernel memory
  disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These flaws occurs due to the specially crafted IOCTL requests
  that can cause the driver to return out of bounds kernel memory.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to leak sensitive
  information such as privileged tokens or kernel memory addresses that may be useful in bypassing
  kernel mitigations. An unprivileged user can run a program from user mode to trigger this
  vulnerability.");

  script_tag(name:"affected", value:"Kaspersky Internet Security version 16.0.0.614 and prior.");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor advisory.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:kaspersky:kaspersky_total_security";

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"16.0.0.614")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
