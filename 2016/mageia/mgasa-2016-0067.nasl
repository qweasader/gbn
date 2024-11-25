# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131236");
  script_cve_id("CVE-2015-8708");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:41 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-12 18:14:24 +0000 (Tue, 12 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0067)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0067");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0067.html");
  script_xref(name:"URL", value:"http://www.thewildbeast.co.uk/claws-mail/bugzilla/show_bug.cgi?id=3557");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17722");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-February/176949.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2015-8708");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'claws-mail' package(s) announced via the MGASA-2016-0067 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated claws-mail fix security vulnerabilities

A stack-based buffer overflow has been found in conv_euctojis() after applying
incomplete patch for CVE-2015-8614. In conv_euctojis() the comparison is with
outlen - 3, but each pass through the loop uses up to 5 bytes and the rest of
the function may add another 4 bytes. The comparison should presumably be
'<= outlen - 9' or equivalently '< outlen - 8'. (CVE-2015-8708)");

  script_tag(name:"affected", value:"'claws-mail' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"claws-mail", rpm:"claws-mail~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-acpi-plugin", rpm:"claws-mail-acpi-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-address_keeper-plugin", rpm:"claws-mail-address_keeper-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-archive-plugin", rpm:"claws-mail-archive-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-att_remover-plugin", rpm:"claws-mail-att_remover-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-attachwarner-plugin", rpm:"claws-mail-attachwarner-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-bogofilter-plugin", rpm:"claws-mail-bogofilter-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-bsfilter-plugin", rpm:"claws-mail-bsfilter-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-clamd-plugin", rpm:"claws-mail-clamd-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-devel", rpm:"claws-mail-devel~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-fancy-plugin", rpm:"claws-mail-fancy-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-fetchinfo-plugin", rpm:"claws-mail-fetchinfo-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-gdata-plugin", rpm:"claws-mail-gdata-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-libravatar-plugin", rpm:"claws-mail-libravatar-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-mailmbox-plugin", rpm:"claws-mail-mailmbox-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-newmail-plugin", rpm:"claws-mail-newmail-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-notification-plugin", rpm:"claws-mail-notification-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pdf_viewer-plugin", rpm:"claws-mail-pdf_viewer-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-perl-plugin", rpm:"claws-mail-perl-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpcore-plugin", rpm:"claws-mail-pgpcore-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpinline-plugin", rpm:"claws-mail-pgpinline-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-pgpmime-plugin", rpm:"claws-mail-pgpmime-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-plugins", rpm:"claws-mail-plugins~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-python-plugin", rpm:"claws-mail-python-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-rssyl-plugin", rpm:"claws-mail-rssyl-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-smime-plugin", rpm:"claws-mail-smime-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-spam_report-plugin", rpm:"claws-mail-spam_report-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-spamassassin-plugin", rpm:"claws-mail-spamassassin-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-tnef_parse-plugin", rpm:"claws-mail-tnef_parse-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-tools", rpm:"claws-mail-tools~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-vcalendar-plugin", rpm:"claws-mail-vcalendar-plugin~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"claws-mail-vcalendar-plugin-devel", rpm:"claws-mail-vcalendar-plugin-devel~3.11.1~3.1.mga5", rls:"MAGEIA5"))) {
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
