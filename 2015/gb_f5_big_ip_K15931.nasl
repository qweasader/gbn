# Copyright (C) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105160");
  script_cve_id("CVE-2014-8602");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2023-03-10T10:20:36+0000");

  script_name("F5 BIG-IP - Unbound vulnerability CVE-2014-8602");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K15931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71589");

  script_tag(name:"impact", value:"An attacker with a properly configured authority server could cause a denial-of-service
  using a crafted DNS recursive query, designed to follow an endless series of delegations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Iterator.c in NLnet Labs Unbound before 1.5.1 does not limit delegation chaining,
  which allows remote attackers to cause a denial of service (memory and CPU consumption) via a large or infinite number
  of referrals.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"last_modification", value:"2023-03-10 10:20:36 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"creation_date", value:"2015-01-09 14:08:36 +0100 (Fri, 09 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

check_f5["LTM"] = make_array("affected",   "11.6.0;11.2.0-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF4;11.5.3;11.5.1_HF7;11.5.0_HF7;11.4.1_HF7;11.4.0_HF10;11.2.1_HF14;11.0.0-11.1.0;10.1.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
