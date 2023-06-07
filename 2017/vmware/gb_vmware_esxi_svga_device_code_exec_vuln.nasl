###############################################################################
# OpenVAS Vulnerability Test
#
# VMware ESXi SVGA Device Code Execution Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811839");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-4924");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-03 19:44:00 +0000 (Thu, 03 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-09-22 12:05:44 +0530 (Fri, 22 Sep 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("VMware ESXi SVGA Device Code Execution Vulnerability (VMSA-2017-0015)");

  script_tag(name:"summary", value:"VMware ESXi is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds write
  error in SVGA device.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  guest to execute code on the host.");

  script_tag(name:"affected", value:"VMware ESXi 6.5 before ESXi650-201707101-SG.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.vmware.com/security/advisories/VMSA-2017-0015.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100843");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("6.5.0", "VIB:esx-base:6.5.0-0.23.5969300");

if(!patches[esxVersion])
  exit(99);

# https://esxi-patches.v-front.de/ESXi-6.5.0.html
if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
