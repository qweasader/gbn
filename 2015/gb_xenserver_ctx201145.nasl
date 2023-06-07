###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer Multiple Security Updates (CTX201145)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105296");
  script_cve_id("CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-2756", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2020-04-02T13:53:24+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX201145)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX201145");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer that may allow a malicious administrator
  of a guest VM to crash the host. These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including
  Citrix XenServer 6.5 Service Pack 1.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2015-4106: Unmediated PCI register access in qemu.

  - CVE-2015-4163: GNTTABOP_swap_grant_ref operation misbehavior.

  - CVE-2015-4164: vulnerability in the iret hypercall handler

  - CVE-2015-2756: Unmediated PCI command register access in qemu

  - CVE-2015-4103: Potential unintended writes to host MSI message data field via qemu.

  - CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests.

  - CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error messages");

  script_tag(name:"affected", value:"XenServer 6.5

  XenServer 6.2.0

  XenServer 6.0

  XenServer 6.0.2

  XenServer 6.1.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2015-06-12 16:17:32 +0200 (Fri, 12 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") )
  exit( 0 );

patches = make_array();

patches['6.5.0'] = make_list( 'XS65E010', 'XS65ESP1004' );
patches['6.2.0'] = make_list( 'XS62ESP1027' );
patches['6.1.0'] = make_list( 'XS61E054' );
patches['6.0.2'] = make_list( 'XS602E044' );
patches['6.0.0'] = make_list( 'XS60E049' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
