# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.120179");
  script_cve_id("CVE-2012-0957", "CVE-2012-1568", "CVE-2012-2133", "CVE-2012-3400", "CVE-2012-3511", "CVE-2012-4508", "CVE-2012-4565");
  script_tag(name:"creation_date", value:"2015-09-08 11:19:19 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-06T14:03:07+0000");
  script_tag(name:"last_modification", value:"2022-01-06 14:03:07 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-142");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-142.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ALAS-2012-142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in the Linux kernel's memory management subsystem in the way quota handling for huge pages was performed. A local, unprivileged user could use this flaw to cause a denial of service or, potentially, escalate their privileges. (CVE-2012-2133, Moderate)

A use-after-free flaw was found in the madvise() system call implementation in the Linux kernel. A local, unprivileged user could use this flaw to cause a denial of service or, potentially, escalate their privileges. (CVE-2012-3511, Moderate)

It was found that when running a 32-bit binary that uses a large number of shared libraries, one of the libraries would always be loaded at a predictable address in memory. An attacker could use this flaw to bypass the Address Space Layout Randomization (ASLR) security feature. (CVE-2012-1568, Low)

Buffer overflow flaws were found in the udf_load_logicalvol() function in the Universal Disk Format (UDF) file system implementation in the Linux kernel. An attacker with physical access to a system could use these flaws to cause a denial of service or escalate their privileges. (CVE-2012-3400, Low)");

  script_tag(name:"affected", value:"'kernel' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.2.34~55.46.amzn1", rls:"AMAZON"))) {
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
