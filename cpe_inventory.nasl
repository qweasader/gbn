# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810002");
  script_version("2022-07-27T10:11:28+0000");
  script_tag(name:"last_modification", value:"2022-07-27 10:11:28 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-11-18 11:43:05 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CPE Inventory");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");

  script_xref(name:"URL", value:"https://nvd.nist.gov/products/cpe");

  script_tag(name:"summary", value:"This routine uses information collected by other routines about
  CPE identities of operating systems, services and applications detected during the scan.

  Note: Some CPEs for specific products might show up twice or more in the output. Background:

  After a product got renamed or a specific vendor was acquired by another one it might happen that
  a product gets a new CPE within the NVD CPE Dictionary but older entries are kept with the older
  CPE.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

ip = get_host_ip();

report = ''; # nb: To make openvas-nasl-lint happy...
cpes = host_details_cpes();

# Sort to not report changes on delta reports if just the order is different
cpes = sort( cpes );

# update the report with CPE's registered as host details
foreach cpe( cpes ) {
  if( cpe >!< report ) {
    report += ip + '|' + cpe + '\n';
  }
}

if( report != '' ) {
  set_kb_item( name:"cpe_inventory/available", value:TRUE );
  log_message( proto:"CPE-T", data:report );
}

exit( 0 );
