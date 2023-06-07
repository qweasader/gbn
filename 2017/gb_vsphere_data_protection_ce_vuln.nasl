###############################################################################
# OpenVAS Vulnerability Test
#
# VMware vSphere Data Protection Command Execution and Information Disclosure Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:vmware:vsphere_data_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107217");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-06-13 13:41:13 +0200 (Tue, 13 Jun 2017)");
  script_cve_id("CVE-2017-4914", "CVE-2017-4917");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");

  script_tag(name:"qod_type", value:"package");
  script_name("VMware vSphere Data Protection Command Execution and Information Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"VMware vSphere Data Protection is prone
  to an arbitrary command-execution and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"VMware vSphere Data Protection is prone to
  an arbitrary command-execution and information disclosure vulnerabilities.
  An attacker can exploit this issue to execute arbitrary command on the affected
  system. This may aid in further attacks.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute
  arbitrary command on the affected system. This may aid in further attacks.
  Attacker can also gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"VMWare vSphere Data Protection 5.5.x before
  6.0.5, 5.8.x before 6.0.5, 6.0.x before 6.0.5, 6.1.x before 6.1.4");
  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98939");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98936");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");
  script_dependencies("gb_vmware_vsphere_data_protection_version.nasl");
  script_mandatory_keys("vmware/vSphere_Data_Protection/version");
  exit(0);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if (Ver =~ "^5\.5\.")
{
  VULN = TRUE;
  fix = "6.0.5";
}
else if(Ver =~ "^5\.8\.")
{
  VULN = TRUE;
  fix = "6.0.5";
}
else if((Ver =~ "^6\.1\.") && (version_is_less(version:Ver, test_version:"6.1.4")))
{
  VULN = TRUE;
  fix = "6.1.4";
}
else if((Ver =~ "^6\.0\.") && (version_is_less(version:Ver, test_version:"6.0.5")))
{
  VULN = TRUE;
  fix = "6.0.5";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
