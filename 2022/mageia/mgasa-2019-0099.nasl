# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0099");
  script_cve_id("CVE-2017-12194", "CVE-2018-10873", "CVE-2018-10893");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 15:13:05 +0000 (Thu, 12 Apr 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0099)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0099");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0099.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/08/17/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23466");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-04/msg00011.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-09/msg00007.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-09/msg00010.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3659-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-gtk' package(s) announced via the MGASA-2019-0099 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way spice-client processed certain messages sent
from the server. An attacker, having control of malicious spice-server,
could use this flaw to crash the client or execute arbitrary code with
permissions of the user running the client. spice-gtk versions through
0.34 are believed to be vulnerable. (CVE-2017-12194)

A vulnerability was discovered in SPICE before version 0.14.1 where the
generated code used for demarshalling messages lacked sufficient bounds
checks. A malicious client or server, after authentication, could send
specially crafted messages to its peer which would result in a crash or,
potentially, other impacts. (CVE-2018-10873)

Multiple integer overflow and buffer overflow issues were discovered in
spice-client's handling of LZ compressed frames. A malicious server could
cause the client to crash or, potentially, execute arbitrary code.
(CVE-2018-10893)");

  script_tag(name:"affected", value:"'spice-gtk' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib-gir2.0", rpm:"lib64spice-client-glib-gir2.0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-glib2.0_8", rpm:"lib64spice-client-glib2.0_8~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk-gir3.0", rpm:"lib64spice-client-gtk-gir3.0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-client-gtk3.0_5", rpm:"lib64spice-client-gtk3.0_5~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-controller0", rpm:"lib64spice-controller0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64spice-gtk-devel", rpm:"lib64spice-gtk-devel~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib-gir2.0", rpm:"libspice-client-glib-gir2.0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-glib2.0_8", rpm:"libspice-client-glib2.0_8~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk-gir3.0", rpm:"libspice-client-gtk-gir3.0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-client-gtk3.0_5", rpm:"libspice-client-gtk3.0_5~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-controller0", rpm:"libspice-controller0~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspice-gtk-devel", rpm:"libspice-gtk-devel~0.33~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.33~3.1.mga6", rls:"MAGEIA6"))) {
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
