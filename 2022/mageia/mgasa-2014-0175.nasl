# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0175");
  script_cve_id("CVE-2013-6370", "CVE-2013-6371");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0175)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0175");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0175.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13179");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1032311");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1032322");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'json-c' package(s) announced via the MGASA-2014-0175 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated json-c packages fix security vulnerabilities:

Florian Weimer reported that the printbuf APIs used in the json-c library used
ints for counting buffer lengths, which is inappropriate for 32bit
architectures. These functions need to be changed to using size_t if possible
for sizes, or to be hardened against negative values if not. This could be
used to cause a denial of service in an application linked to the json-c
library (CVE-2013-6370).

Florian Weimer reported that the hash function in the json-c library was weak,
and that parsing smallish JSON strings showed quadratic timing behaviour.
This could cause an application linked to the json-c library, and that
processes some specially-crafted JSON data, to use excessive amounts of CPU
(CVE-2013-6371).");

  script_tag(name:"affected", value:"'json-c' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"json-c", rpm:"json-c~0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64json-devel", rpm:"lib64json-devel~0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64json2", rpm:"lib64json2~0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjson-devel", rpm:"libjson-devel~0.11~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjson2", rpm:"libjson2~0.11~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"json-c", rpm:"json-c~0.11~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64json-devel", rpm:"lib64json-devel~0.11~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64json2", rpm:"lib64json2~0.11~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjson-devel", rpm:"libjson-devel~0.11~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjson2", rpm:"libjson2~0.11~3.1.mga4", rls:"MAGEIA4"))) {
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
