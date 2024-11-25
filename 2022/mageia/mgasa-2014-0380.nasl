# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0380");
  script_cve_id("CVE-2014-0103", "CVE-2014-5447", "CVE-2014-5448", "CVE-2014-5449", "CVE-2014-5450");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 14:56:12 +0000 (Fri, 20 Apr 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0380");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0380.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13822");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-August/137158.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zarafa' package(s) announced via the MGASA-2014-0380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated zarafa packages fix security vulnerabilities:

Robert Scheck reported that Zarafa's WebAccess stored session information,
including login credentials, on-disk in PHP session files. This session file
would contain a user's username and password to the Zarafa IMAP server
(CVE-2014-0103).

Robert Scheck discovered that the Zarafa Collaboration Platform has multiple
incorrect default permissions (CVE-2014-5447, CVE-2014-5448, CVE-2014-5449,
CVE-2014-5450).");

  script_tag(name:"affected", value:"'zarafa' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64zarafa-devel", rpm:"lib64zarafa-devel~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zarafa0", rpm:"lib64zarafa0~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzarafa-devel", rpm:"libzarafa-devel~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzarafa0", rpm:"libzarafa0~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mapi", rpm:"php-mapi~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-MAPI", rpm:"python-MAPI~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa", rpm:"zarafa~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-archiver", rpm:"zarafa-archiver~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-caldav", rpm:"zarafa-caldav~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-client", rpm:"zarafa-client~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-common", rpm:"zarafa-common~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-dagent", rpm:"zarafa-dagent~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-gateway", rpm:"zarafa-gateway~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-ical", rpm:"zarafa-ical~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-indexer", rpm:"zarafa-indexer~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-monitor", rpm:"zarafa-monitor~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-server", rpm:"zarafa-server~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-spooler", rpm:"zarafa-spooler~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-utils", rpm:"zarafa-utils~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-webaccess", rpm:"zarafa-webaccess~7.1.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64zarafa-devel", rpm:"lib64zarafa-devel~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zarafa0", rpm:"lib64zarafa0~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzarafa-devel", rpm:"libzarafa-devel~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzarafa0", rpm:"libzarafa0~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mapi", rpm:"php-mapi~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-MAPI", rpm:"python-MAPI~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa", rpm:"zarafa~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-archiver", rpm:"zarafa-archiver~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-caldav", rpm:"zarafa-caldav~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-client", rpm:"zarafa-client~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-common", rpm:"zarafa-common~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-dagent", rpm:"zarafa-dagent~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-gateway", rpm:"zarafa-gateway~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-ical", rpm:"zarafa-ical~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-indexer", rpm:"zarafa-indexer~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-monitor", rpm:"zarafa-monitor~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-server", rpm:"zarafa-server~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-spooler", rpm:"zarafa-spooler~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-utils", rpm:"zarafa-utils~7.1.11~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zarafa-webaccess", rpm:"zarafa-webaccess~7.1.11~1.mga4", rls:"MAGEIA4"))) {
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
