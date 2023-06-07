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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105844");
  script_version("2021-09-20T14:50:00+0000");
  script_tag(name:"last_modification", value:"2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-08-04 16:19:14 +0200 (Thu, 04 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-5094", "CVE-2016-5095");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("F5 BIG-IP - PHP vulnerabilities CVE-2016-5094 and CVE-2016-5095");

  script_category(ACT_GATHER_INFO);

  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to multiple vulnerabilities in PHP.

  This VT has been deprecated as a duplicate of the VT 'F5 BIG-IP - PHP vulnerabilities
  CVE-2016-5094 and CVE-2016-5095' (OID: 1.3.6.1.4.1.25623.1.0.140644).");

  script_tag(name:"insight", value:"- CVE-2016-5094 Integer overflow in the php_html_entities
  function in ext/standard/html.c in PHP before 5.5.36 and 5.6.x before 5.6.22 allows remote
  attackers to cause a denial of service or possibly have unspecified other impact by triggering a
  large output string from the htmlspecialchars function.

  - CVE-2016-5095: Integer overflow in the php_escape_html_entities_ex function in
  ext/standard/html.c in PHP before 5.5.36 and 5.6.x before 5.6.22 allows remote attackers to cause
  a denial of service or possibly have unspecified other impact by triggering a large output string
  from a FILTER_SANITIZE_FULL_SPECIAL_CHARS filter_var call.");

  script_tag(name:"impact", value:"Although BIG-IP software contains the vulnerable code, BIG-IP
  systems do not use the vulnerable code in a way that exposes the vulnerability in a standard
  default configuration. When exploited, the PHP module may encounter an out-of-memory error that
  affects the Configuration utility.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K51390683");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);