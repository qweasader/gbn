# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:cyrus:imap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902223");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-2632");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Cyrus IMAP Server SIEVE Script Handling Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36377");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2559");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2009-September/msg00491.html");
  script_xref(name:"URL", value:"http://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sieve/script.c.diff?r1=1.67&r2=1.68");
  script_xref(name:"URL", value:"http://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sieve/script.c.diff?r1=1.62&r2=1.62.2.1&only_with_tag=cyrus-imapd-2_2-tail");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash an affected server
  or execute arbitrary code via a malicious SIEVE Script.");

  script_tag(name:"affected", value:"Cyrus IMAP Server versions 2.3.14 and prior.");

  script_tag(name:"insight", value:"The flaw is caused is due to error in the handling of 'SIEVE' Script, that
  fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"summary", value:"Cyrus IMAP Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply the patches from the references or upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.3.14" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
