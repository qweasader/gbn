# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103455");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-1083", "CVE-2010-2492", "CVE-2010-2798", "CVE-2010-2938", "CVE-2010-2942",
                "CVE-2010-2943", "CVE-2010-3015", "CVE-2010-3066", "CVE-2010-3067", "CVE-2010-3078",
                "CVE-2010-3086", "CVE-2010-3296", "CVE-2010-3432", "CVE-2010-3442", "CVE-2010-3477",
                "CVE-2010-3699", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3876",
                "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073",
                "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157",
                "CVE-2010-4158", "CVE-2010-4161", "CVE-2010-4238", "CVE-2010-4242", "CVE-2010-4243",
                "CVE-2010-4247", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4251", "CVE-2010-4255",
                "CVE-2010-4263", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4655",
                "CVE-2011-0521", "CVE-2011-0710", "CVE-2011-1010", "CVE-2011-1090", "CVE-2011-1478",
                "CVE-2010-1323", "CVE-2011-0281", "CVE-2011-0282", "CVE-2010-0296", "CVE-2011-0536",
                "CVE-2011-1071", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-1659", "CVE-2011-1494",
                "CVE-2011-1495");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2023-05-18T09:08:59+0000");
  script_name("VMware ESXi/ESX updates to third party libraries and ESX Service Console (VMSA-2011-0012.3)");
  script_tag(name:"last_modification", value:"2023-05-18 09:08:59 +0000 (Thu, 18 May 2023)");
  script_tag(name:"creation_date", value:"2012-03-16 12:42:13 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0012.html");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0012.3.");

  script_tag(name:"affected", value:"ESXi 5.0 without patch ESXi500-201112401-SG

  ESXi 4.1 without patch ESXi410-201110201-SG

  ESX 4.1 without patches ESX410-201110201-SG and ESX410-201110224-SG

  ESXi 4.0 without patch ESXi400-201110401-SG

  ESX 4.0 without patches ESX400-201110401-SG, ESX400-201110403-SG and ESX400-201110409-SG

  ESXi 3.5 without patch ESXe350-201203401-I-SG

  ESX 3.5 without patch ESX350-201203403-SG");

  script_tag(name:"insight", value:"VMware ESXi and ESX updates to third party libraries and ESX Service Console address several security issues.

  a. ESX third party update for Service Console kernel

  This update takes the console OS kernel package to kernel-2.6.18-238.9.1 which resolves multiple security issues.

  b. ESX third party update for Service Console krb5 RPMs

  This patch updates the krb5-libs and krb5-workstation RPMs of the console OS to version 1.6.1-55.el5_6.1, which resolves multiple security issues.

  c. ESXi and ESX update to third party component glibc

  The glibc third-party library is updated to resolve multiple security issues.

  d. ESX update to third party drivers mptsas, mpt2sas, and mptspi

  The mptsas, mpt2sas, and mptspi drivers are updated which addresses multiple security issues in the mpt2sas driver.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"vuldetect", value:"Checks if the target host is missing one or more patch(es).");

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

patches = make_array("4.1.0", "ESXi410-201110201-SG",
                     "4.0.0", "ESXi400-201110401-SG",
                     "5.0.0", "VIB:esx-base:5.0.0-0.3.515841");

if(!patches[esxVersion])
  exit(99);

if(report = esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
