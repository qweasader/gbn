# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0472");
  script_cve_id("CVE-2014-4975", "CVE-2014-8090");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0472");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0472.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2397-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14532");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2014/11/13/rexml-dos-cve-2014-8090/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2014/11/13/ruby-1-9-3-p551-is-released/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2014/11/13/ruby-2-0-0-p598-is-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2014-0472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Will Wood discovered that Ruby incorrectly handled the encodes() function.
An attacker could possibly use this issue to cause Ruby to crash, resulting
in a denial of service, or possibly execute arbitrary code. The default
compiler options for affected releases should reduce the vulnerability to a
denial of service (CVE-2014-4975).

Due to an incomplete fix for CVE-2014-8080, 100% CPU utilization can occur as
a result of recursive expansion with an empty String. When reading text nodes
from an XML document, the REXML parser in Ruby can be coerced into allocating
extremely large string objects which can consume all of the memory on a
machine, causing a denial of service (CVE-2014-8090).");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby1.9", rpm:"lib64ruby1.9~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby1.9", rpm:"libruby1.9~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~1.9.3.p551~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.0", rpm:"lib64ruby2.0~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.0", rpm:"libruby2.0~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~2.0.0.p598~1.mga4", rls:"MAGEIA4"))) {
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
