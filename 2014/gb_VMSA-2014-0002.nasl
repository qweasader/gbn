###############################################################################
# OpenVAS Vulnerability Test
#
# VMSA-2014-0002: VMware vSphere updates to third party libraries
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103915");
  script_cve_id("CVE-2013-5211", "CVE-2013-4332");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2022-05-31T13:45:57+0100");
  script_name("VMware ESXi/ESX updates to third party libraries (VMSA-2014-0002)");
  script_tag(name:"last_modification", value:"2022-05-31 13:45:57 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2014-03-12 14:04:01 +0100 (Wed, 12 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0002.html");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"a. DDoS vulnerability in NTP third party libraries

  The NTP daemon has a DDoS vulnerability in the handling of the
  'monlist' command. An attacker may send a forged request to a
  vulnerable NTP server resulting in an amplified response to the
  intended target of the DDoS attack.

  b. Update to ESXi glibc package

  The ESXi glibc package is updated to version glibc-2.5-118.el5_10.2 to
  resolve a security issue.

  c. vCenter and Update Manager, Oracle JRE 1.7 Update 45

  Oracle JRE is updated to version JRE 1.7 Update 45, which addresses
  multiple security issues that existed in earlier releases of Oracle JRE.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"VMware has updated vSphere third party libraries.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 without patch ESXi550-201403101-SG

  VMware ESXi 5.1 without patch ESXi510-201404101-SG

  VMware ESXi 5.0 without patch ESXi500-201405101-SG

  VMware ESXi 4.1 without patch ESXi410-201404401-SG

  VMware ESXi 4.0 without patch ESXi400-201404401-SG");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("5.5.0", "VIB:esx-base:5.5.0-1.15.1623387",
                     "5.1.0", "VIB:esx-base:5.1.0-2.27.1743201",
                     "5.0.0", "VIB:esx-base:5.0.0-3.47.1749766",
                     "4.0.0", "ESXi400-201404401-SG",
                     "4.1.0", "ESXi410-201404401-SG");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
