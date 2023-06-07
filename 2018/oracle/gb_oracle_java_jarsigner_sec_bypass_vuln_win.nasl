###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE 'jarsigner' Security Bypass Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813376");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2013-4578");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 17:59:00 +0000 (Wed, 17 Jan 2018)");
  script_tag(name:"creation_date", value:"2018-05-23 16:10:50 +0530 (Wed, 23 May 2018)");
  script_name("Oracle Java SE 'jarsigner' Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"Oracle Java SE is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to jarsigner does not
  detect unsigned bytecode injected into signed jars.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject malicious unsigned bytecode into a signed JAR without
  failing jarsigner verification.");

  script_tag(name:"affected", value:"Oracle Java SE version before 7u51 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 7u51 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1031471");
  script_xref(name:"URL", value:"http://hg.openjdk.java.net/jdk7u/jdk7u/jdk/rev/d5f36e1c927e");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^1\.7")
{
  if(version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.50"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Java SE 7u51", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);