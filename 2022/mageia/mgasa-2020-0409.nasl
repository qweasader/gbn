# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0409");
  script_cve_id("CVE-2020-25654");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:40:34 +0000 (Fri, 04 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0409)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0409");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0409.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27472");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1888191");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-10/msg00076.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/10/27/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker' package(s) announced via the MGASA-2020-0409 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ACL restrictions bypass. (CVE-2020-25654)");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64cib4", rpm:"lib64cib4~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64crmcluster4", rpm:"lib64crmcluster4~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64crmcommon3", rpm:"lib64crmcommon3~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64crmservice3", rpm:"lib64crmservice3~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lrmd1", rpm:"lib64lrmd1~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pacemaker-devel", rpm:"lib64pacemaker-devel~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pe_rules2", rpm:"lib64pe_rules2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pe_status10", rpm:"lib64pe_status10~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pengine10", rpm:"lib64pengine10~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64stonithd2", rpm:"lib64stonithd2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64transitioner2", rpm:"lib64transitioner2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcib4", rpm:"libcib4~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrmcluster4", rpm:"libcrmcluster4~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrmcommon3", rpm:"libcrmcommon3~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcrmservice3", rpm:"libcrmservice3~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblrmd1", rpm:"liblrmd1~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpacemaker-devel", rpm:"libpacemaker-devel~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpe_rules2", rpm:"libpe_rules2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpe_status10", rpm:"libpe_status10~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpengine10", rpm:"libpengine10~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstonithd2", rpm:"libstonithd2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtransitioner2", rpm:"libtransitioner2~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker", rpm:"pacemaker~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cts", rpm:"pacemaker-cts~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-doc", rpm:"pacemaker-doc~1.1.19~2.2.mga7", rls:"MAGEIA7"))) {
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
