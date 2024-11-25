# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0398");
  script_cve_id("CVE-2013-4002");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0398)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0398");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0398.html");
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/mbs1/MDVSA-2014%3A193/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14176");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-1319.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2' package(s) announced via the MGASA-2014-0398 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xerces-j2 packages fix security vulnerability:

A resource consumption issue was found in the way Xerces-J handled
XML declarations. A remote attacker could use an XML document with
a specially crafted declaration using a long pseudo-attribute name
that, when parsed by an application using Xerces-J, would cause that
application to use an excessive amount of CPU (CVE-2013-4002).");

  script_tag(name:"affected", value:"'xerces-j2' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.11.0~8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-demo", rpm:"xerces-j2-demo~2.11.0~8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc", rpm:"xerces-j2-javadoc~2.11.0~8.1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.11.0~10.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-demo", rpm:"xerces-j2-demo~2.11.0~10.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2-javadoc", rpm:"xerces-j2-javadoc~2.11.0~10.1.mga4", rls:"MAGEIA4"))) {
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
