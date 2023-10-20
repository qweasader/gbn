# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0460");
  script_cve_id("CVE-2013-2298");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0460)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0460");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0460.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12129");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-December/125125.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=9108");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=9109");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boinc-client' package(s) announced via the MGASA-2014-0460 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple stack overflow flaws were found in the way the XML parser of
boinc-client, a Berkeley Open Infrastructure for Network Computing (BOINC)
client for distributed computing, performed processing of certain XML files.
A rogue BOINC server could provide a specially-crafted XML file that, when
processed would lead to boinc-client executable crash (CVE-2013-2298).

Issues preventing the boinc-client service from working immediately after
installation have been fixed as well.");

  script_tag(name:"affected", value:"'boinc-client' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"boinc-client", rpm:"boinc-client~7.2.42~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-devel", rpm:"boinc-client-devel~7.2.42~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-doc", rpm:"boinc-client-doc~7.2.42~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-static", rpm:"boinc-client-static~7.2.42~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-manager", rpm:"boinc-manager~7.2.42~1.2.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"boinc-client", rpm:"boinc-client~7.2.42~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-devel", rpm:"boinc-client-devel~7.2.42~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-doc", rpm:"boinc-client-doc~7.2.42~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-client-static", rpm:"boinc-client-static~7.2.42~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boinc-manager", rpm:"boinc-manager~7.2.42~1.2.mga4", rls:"MAGEIA4"))) {
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
