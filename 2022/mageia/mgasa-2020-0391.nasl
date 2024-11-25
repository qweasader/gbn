# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0391");
  script_cve_id("CVE-2020-16094");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 14:27:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0391)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0391");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0391.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27427");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JUBLHUG2UCXVABAGN5FVTD3AB3YKE5NN/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'claws-mail' package(s) announced via the MGASA-2020-0391 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In imap_scan_tree_recursive in Claws Mail through 3.17.6, a malicious IMAP
server can trigger stack consumption because of unlimited recursion into
subdirectories during a rebuild of the folder tree (CVE-2020-16094).");

  script_tag(name:"affected", value:"'claws-mail' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-acpi-plugin", rpm:"claws-mail-acpi-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-address_keeper-plugin", rpm:"claws-mail-address_keeper-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-archive-plugin", rpm:"claws-mail-archive-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-att_remover-plugin", rpm:"claws-mail-att_remover-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-attachwarner-plugin", rpm:"claws-mail-attachwarner-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-bogofilter-plugin", rpm:"claws-mail-bogofilter-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-bsfilter-plugin", rpm:"claws-mail-bsfilter-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-clamd-plugin", rpm:"claws-mail-clamd-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-dillo-plugin", rpm:"claws-mail-dillo-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-fetchinfo-plugin", rpm:"claws-mail-fetchinfo-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-gdata-plugin", rpm:"claws-mail-gdata-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-libravatar-plugin", rpm:"claws-mail-libravatar-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-litehtml_viewer-plugin", rpm:"claws-mail-litehtml_viewer-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-mailmbox-plugin", rpm:"claws-mail-mailmbox-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-managesieve-plugin", rpm:"claws-mail-managesieve-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-newmail-plugin", rpm:"claws-mail-newmail-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-notification-plugin", rpm:"claws-mail-notification-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pdf_viewer-plugin", rpm:"claws-mail-pdf_viewer-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-perl-plugin", rpm:"claws-mail-perl-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpcore-plugin", rpm:"claws-mail-pgpcore-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpinline-plugin", rpm:"claws-mail-pgpinline-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpmime-plugin", rpm:"claws-mail-pgpmime-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-plugins", rpm:"claws-mail-plugins~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-python-plugin", rpm:"claws-mail-python-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-rssyl-plugin", rpm:"claws-mail-rssyl-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-smime-plugin", rpm:"claws-mail-smime-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-spam_report-plugin", rpm:"claws-mail-spam_report-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-spamassassin-plugin", rpm:"claws-mail-spamassassin-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-tools", rpm:"claws-mail-tools~3.17.7~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-vcalendar-plugin", rpm:"claws-mail-vcalendar-plugin~3.17.7~1.mga7", rls:"MAGEIA7"))) {
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
