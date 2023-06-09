# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103864");
  script_cve_id("CVE-2013-5973");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2022-09-21T10:12:28+0000");
  script_name("VMware ESXi/ESX unauthorized file access through vCenter Server and ESX (VMSA-2013-0016) - Remote Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0016.html");

  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"creation_date", value:"2013-12-27 12:04:01 +0100 (Fri, 27 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_tag(name:"summary", value:"VMware ESXi and ESX unauthorized file access through vCenter
  Server and ESX.");

  script_tag(name:"vuldetect", value:"Checks the build number.");

  script_tag(name:"insight", value:"VMware ESXi and ESX contain a vulnerability in the handling of
  certain Virtual Machine file descriptors. This issue may allow an unprivileged vCenter Server
  user with the privilege 'Add Existing Disk' to obtain read and write access to arbitrary files on
  ESXi or ESX. On ESX, an unprivileged local user may obtain read and write access to arbitrary
  files. Modifying certain files may allow for code execution after a host reboot.

  Unprivileged vCenter Server users or groups that are assigned the predefined role
  'Virtual Machine Power User' or 'Resource Pool Administrator' have the privilege
  'Add Existing Disk'.

  The issue cannot be exploited through VMware vCloud Director.");

  script_tag(name:"affected", value:"VMware ESXi 5.5 Build < 1474526

  VMware ESXi 5.1 Build < 1312874

  VMware ESXi 5.0 Build < 1311177");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

if(!esxBuild = get_kb_item("VMware/ESX/build"))
  exit(0);

fixed_builds = make_array("5.0.0","1311177",
                          "5.1.0","1312874",
                          "5.5.0","1474526");

if(!fixed_builds[esxVersion])
  exit(0);

if(int(esxBuild) < int(fixed_builds[esxVersion])) {
  security_message(port:0, data:esxi_remote_report(ver:esxVersion, build:esxBuild, fixed_build:fixed_builds[esxVersion]));
  exit(0);
}

exit(99);
