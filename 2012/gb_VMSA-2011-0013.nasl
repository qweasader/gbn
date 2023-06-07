###############################################################################
# OpenVAS Vulnerability Test
#
# VMSA-2011-0013.2 VMware third party component updates for VMware vCenter Server, vSphere Update Manager, ESXi and ESX
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103451");
  script_cve_id("CVE-2008-7270", "CVE-2010-4180", "CVE-2011-0002", "CVE-2010-3170", "CVE-2010-3173", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4451", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4474", "CVE-2010-4475", "CVE-2010-4476", "CVE-2011-0862", "CVE-2011-0873", "CVE-2011-0815", "CVE-2011-0864", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0871", "CVE-2011-0867", "CVE-2011-0865", "CVE-2010-2054");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2020-11-19T14:17:11+0000");
  script_name("VMware ESXi/ESX third party component updates (VMSA-2011-0013.2)");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2012-03-15 18:41:24 +0100 (Thu, 15 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0013.html");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0013.2.");

  script_tag(name:"affected", value:"ESXi 4.1 without patch ESX410-201110201-SG

  ESX 4.1 without patches ESX410-201110201-SG, ESX410-201110204-SG, ESX410-201110206-SG, ESX410-201110214-SG

  ESX 4.0 without patch ESX400-201111201-SG");

  script_tag(name:"insight", value:"a. ESX third party update for Service Console openssl RPM

  The Service Console openssl RPM is updated to openssl-0.9.8e.12.el5_5.7
  resolving two security issues.

  b. ESX third party update for Service Console libuser RPM

  The Service Console libuser RPM is updated to version 0.54.7-2.1.el5_5.2 to
  resolve a security issue.

  c. ESX third party update for Service Console nss and nspr RPMs

  The Service Console Network Security Services (NSS) and Netscape Portable
  Runtime (NSPR) libraries are updated to nspr-4.8.6-1 and nss-3.12.8-4 resolving
  multiple security issues.

  d. vCenter Server and ESX, Oracle (Sun) JRE update 1.6.0_24

  Oracle (Sun) JRE is updated to version 1.6.0_24, which addresses multiple
  security issues that existed in earlier releases of Oracle (Sun) JRE.

  e. vSphere Update Manager Oracle (Sun) JRE update 1.5.0_30

  Oracle (Sun) JRE is updated to version 1.5.0_30, which addresses multiple
  security issues that existed in earlier releases of Oracle (Sun) JRE.

  f. Integer overflow in VMware third party component sfcb

  This release resolves an integer overflow issue present in the third party
  library SFCB when the httpMaxContentLength has been changed from its default
  value to 0 in /etc/sfcb/sfcb.cfg. The integer overflow could allow remote
  attackers to cause a denial of service (heap memory corruption) or possibly
  execute arbitrary code via a large integer in the Content-Length HTTP header.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("vmware_esx.inc");

if(!get_kb_item("VMware/ESXi/LSC"))
  exit(0);

if(!esxVersion = get_kb_item("VMware/ESX/version"))
  exit(0);

patches = make_array("4.1.0", "ESX410-201110201-SG");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
