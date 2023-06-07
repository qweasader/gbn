# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105514");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2021-05-03T13:21:59+0000");

  script_name("F5 BIG-IP - GRUB2 vulnerability CVE-2015-8370");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K25901386");

  script_tag(name:"impact", value:"This vulnerability can be exploited under certain circumstances, allowing physically proximate attackers to bypass the system's access authentication. By default, the GRUB2 configuration used in F5 products does not expose this issue. The customization of GRUB2 configurations is not supported.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer underflows in Grub2 1.98 through 2.02 allow physically proximate attackers to bypass authentication, obtain sensitive information, or cause a denial of service (disk corruption) via backspace characters in the (1) grub_username_get function in grub-core/normal/auth.c or the (2) grub_password_get function in lib/crypto.c, which trigger an 'Off-by-two' or 'Out of bounds overwrite' memory error.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-05-03 13:21:59 +0000 (Mon, 03 May 2021)");
  script_tag(name:"creation_date", value:"2016-01-19 11:40:40 +0100 (Tue, 19 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("list_array_func.inc");
include("f5.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

check_f5["LTM"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["AVR"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;");

check_f5["APM"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "12.0.0;11.3.0-11.6.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["PSM"] = make_array("affected",   "11.3.0-11.4.1;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.3.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.3.0;",
                             "unaffected", "11.0.0-11.2.1;10.1.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
