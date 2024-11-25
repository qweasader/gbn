# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856309");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2024-34702", "CVE-2024-34703", "CVE-2024-39312");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-17 04:01:47 +0000 (Wed, 17 Jul 2024)");
  script_name("openSUSE: Security Advisory for Botan (openSUSE-SU-2024:0201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0201-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6IOSLFSD2TJGWL4XB37VIQSVW7SPG2IP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Botan'
  package(s) announced via the openSUSE-SU-2024:0201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Botan fixes the following issues:

     Update to 2.19.5:

  * Fix multiple Denial of service attacks due to X.509 cert processing:

  * CVE-2024-34702 - boo#1227238

  * CVE-2024-34703 - boo#1227607

  * CVE-2024-39312 - boo#1227608

  * Fix a crash in OCB

  * Fix a test failure in compression with certain versions of zlib

  * Fix some iterator debugging errors in TLS CBC decryption.

  * Avoid a miscompilation in ARIA when using XCode 14");

  script_tag(name:"affected", value:"'Botan' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"Botan", rpm:"Botan~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19", rpm:"libbotan-2-19~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-botan", rpm:"python3-botan~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-64bit", rpm:"libbotan-2-19-64bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-64bit", rpm:"libbotan-devel-64bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-32bit", rpm:"libbotan-2-19-32bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-32bit", rpm:"libbotan-devel-32bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Botan-doc", rpm:"Botan-doc~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Botan", rpm:"Botan~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19", rpm:"libbotan-2-19~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-botan", rpm:"python3-botan~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-64bit", rpm:"libbotan-2-19-64bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-64bit", rpm:"libbotan-devel-64bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-2-19-32bit", rpm:"libbotan-2-19-32bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel-32bit", rpm:"libbotan-devel-32bit~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Botan-doc", rpm:"Botan-doc~2.19.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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