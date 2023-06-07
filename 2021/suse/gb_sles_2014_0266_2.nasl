# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0266.2");
  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5887", "CVE-2013-5888", "CVE-2013-5889", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0387", "CVE-2014-0403", "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424", "CVE-2014-0428");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0266-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0266-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140266-2/");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/#Oracle_Ja");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java 6' package(s) announced via the SUSE-SU-2014:0266-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 6 was updated to version SR15-FP1 which received security and bug fixes.

More information at:
[link moved to references] nuary_14_2014_CPU anuary_14_2014_CPU>

Security Issue references:

 * CVE-2014-0428
>
 * CVE-2014-0422
>
 * CVE-2013-5907
>
 * CVE-2014-0417
>
 * CVE-2014-0373
>
 * CVE-2014-0423
>
 * CVE-2014-0376
>
 * CVE-2014-0376
>
 * CVE-2014-0416
>
 * CVE-2014-0368
>
 * CVE-2014-0411
>
 * CVE-2014-0428
>
 * CVE-2014-0422
>
 * CVE-2013-5907
>
 * CVE-2014-0415
>
 * CVE-2014-0410
>
 * CVE-2013-5889
>
 * CVE-2014-0417
>
 * CVE-2014-0387
>
 * CVE-2014-0424
>
 * CVE-2013-5878
>
 * CVE-2014-0373
>
 * CVE-2014-0375
>
 * CVE-2014-0403
>
 * CVE-2014-0423
>
 * CVE-2014-0376
>
 * CVE-2013-5910
>
 * CVE-2013-5884
>
 * CVE-2013-5896
>
 * CVE-2014-0376
>
 * CVE-2013-5899
>
 * CVE-2014-0416
>
 * CVE-2013-5887
>
 * CVE-2014-0368
>
 * CVE-2013-5888
>
 * CVE-2013-5898
>
 * CVE-2014-0411
>");

  script_tag(name:"affected", value:"'IBM Java 6' package(s) on SUSE Linux Enterprise Server 11-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr6.1~0.8.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
