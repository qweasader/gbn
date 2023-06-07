# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113348");
  script_version("2021-09-20T14:50:00+0000");
  script_tag(name:"last_modification", value:"2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-02-28 11:04:44 +0100 (Thu, 28 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-26 16:52:00 +0000 (Tue, 26 Feb 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-9168");

  script_name("WordPress WooCommerce Plugin < 3.5.5 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"The WooCommerce plugin for WordPress is prone
  to a Cross-Site Scripting (XSS) vulnerability.

  This VT has been merged into the VT 'WordPress WooCommerce Plugin < 3.5.5 XSS Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.113347).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability resides within the Photoswipe caption.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary JavaScript and HTML into the site.");

  script_tag(name:"affected", value:"WooCommerce plugin through version 3.5.4.");

  script_tag(name:"solution", value:"Update to version 3.5.5.");

  script_xref(name:"URL", value:"https://woocommerce.wordpress.com/2019/02/20/woocommerce-3-5-5-security-fix-release/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
