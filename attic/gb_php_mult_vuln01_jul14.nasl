# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804683");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2014-3478", "CVE-2014-3515", "CVE-2014-0207", "CVE-2014-3487",
                "CVE-2014-3479", "CVE-2014-3480");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-18 16:56:10 +0530 (Fri, 18 Jul 2014)");
  script_name("PHP Multiple Vulnerabilities - 01 - Jul14");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.

  This VT has been merged into the VTs 'PHP Multiple Vulnerabilities (Jun/Aug 2014) - Linux' (OID:
  1.3.6.1.4.1.25623.1.0.809736) and 'PHP Multiple Vulnerabilities (Jun/Aug 2014) - Windows' (OID:
  1.3.6.1.4.1.25623.1.0.809735).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - A buffer overflow in the 'mconvert' function in softmagic.c script.

  - Two type confusion errors when deserializing ArrayObject and SPLObjectStorage objects.

  - An unspecified boundary check issue in the 'cdf_read_short_sector' function related to Fileinfo.

  - Some boundary checking issues in the 'cdf_read_property_info', 'cdf_count_chain' and
  'cdf_check_stream_offset' functions in cdf.c related to Fileinfo.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
  service attacks or potentially execute arbitrary code.");

  script_tag(name:"affected", value:"PHP version 5.4.x before 5.4.30 and 5.5.x before 5.5.14");

  script_tag(name:"solution", value:"Update to PHP version 5.4.30 or 5.5.14 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68238");
  script_xref(name:"URL", value:"http://secunia.com/advisories/59575");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);