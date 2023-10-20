# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0158");
  script_cve_id("CVE-2017-0386", "CVE-2017-0553");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0158)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0158");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0158.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20168");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JR5R2FSPYCLDAHTXQC2LKY74N5YW2PQQ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/KIHASXRQO2YTQPKVP4VGIB2XHPANG6YX/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnl3' package(s) announced via the MGASA-2017-0158 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An elevation of privilege vulnerability in the libnl library could enable
a local malicious application to execute arbitrary code within the context
of a privileged process (CVE-2017-0386).

An integer overflow vulnerability was found in nlmsg_reserve() triggered
by crafted @len argument resulting into reserving too few bytes
(CVE-2017-0553).");

  script_tag(name:"affected", value:"'libnl3' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64nl-cli3_200", rpm:"lib64nl-cli3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl-genl3_200", rpm:"lib64nl-genl3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl-idiag3_200", rpm:"lib64nl-idiag3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl-nf3_200", rpm:"lib64nl-nf3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl-route3_200", rpm:"lib64nl-route3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl3-devel", rpm:"lib64nl3-devel~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nl3_200", rpm:"lib64nl3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl-cli3_200", rpm:"libnl-cli3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl-genl3_200", rpm:"libnl-genl3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl-idiag3_200", rpm:"libnl-idiag3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl-nf3_200", rpm:"libnl-nf3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl-route3_200", rpm:"libnl-route3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl3", rpm:"libnl3~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl3-config", rpm:"libnl3-config~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl3-devel", rpm:"libnl3-devel~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl3-tools", rpm:"libnl3-tools~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnl3_200", rpm:"libnl3_200~3.2.25~3.1.mga5", rls:"MAGEIA5"))) {
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
