# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0789.1");
  script_cve_id("CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0789-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0789-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150789-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk, java-1_7_0-openjdk-bootstrap' package(s) announced via the SUSE-SU-2015:0789-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenJDK was updated to 2.5.5 - OpenJdk 7u79 to fix security issues and bugs:
The following vulnerabilities were fixed:
* CVE-2015-0458: Deployment: unauthenticated remote attackers could
 execute arbitrary code via multiple protocols.
* CVE-2015-0459: 2D: unauthenticated remote attackers could execute
 arbitrary code via multiple protocols.
* CVE-2015-0460: Hotspot: unauthenticated remote attackers could execute
 arbitrary code via multiple protocols.
* CVE-2015-0469: 2D: unauthenticated remote attackers could execute
 arbitrary code via multiple protocols.
* CVE-2015-0477: Beans: unauthenticated remote attackers could update,
 insert or delete some JAVA accessible data via multiple protocols
* CVE-2015-0478: JCE: unauthenticated remote attackers could read some
 JAVA accessible data via multiple protocols
* CVE-2015-0480: Tools: unauthenticated remote attackers could update,
 insert or delete some JAVA accessible data via multiple protocols and
 cause a partial denial of service (partial DOS)
* CVE-2015-0484: JavaFX: unauthenticated remote attackers could read,
 update, insert or delete access some Java accessible data via multiple
 protocols and cause a partial denial of service (partial DOS).
* CVE-2015-0488: JSSE: unauthenticated remote attackers could cause a
 partial denial of service (partial DOS).
* CVE-2015-0491: 2D: unauthenticated remote attackers could execute
 arbitrary code via multiple protocols.
* CVE-2015-0492: JavaFX: unauthenticated remote attackers could execute
 arbitrary code via multiple protocols.");

  script_tag(name:"affected", value:"'java-1_7_0-openjdk, java-1_7_0-openjdk-bootstrap' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.79~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.79~15.1", rls:"SLES12.0"))) {
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
