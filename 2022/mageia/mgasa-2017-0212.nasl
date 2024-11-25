# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0212");
  script_cve_id("CVE-2017-7507", "CVE-2017-7869");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 13:23:08 +0000 (Tue, 25 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0212)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0212");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0212.html");
  script_xref(name:"URL", value:"http://www.gnutls.org/security.html#GNUTLS-SA-2017-3");
  script_xref(name:"URL", value:"http://www.gnutls.org/security.html#GNUTLS-SA-2017-4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20417");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-07/msg00064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the MGASA-2017-0212 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GnuTLS before 2017-02-20 has an out-of-bounds write caused by an integer
overflow and heap-based buffer overflow related to the cdk_pkt_read
function in opencdk/read-packet.c. This issue (which is a subset of the
vendor's GNUTLS-SA-2017-3 report) is fixed in 3.5.10. (CVE-2017-7869)

GnuTLS version 3.5.12 and earlier is vulnerable to a NULL pointer
dereference while decoding a status response TLS extension with valid
contents. This could lead to a crash of the GnuTLS server application.
(CVE-2017-7507)");

  script_tag(name:"affected", value:"'gnutls' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-ssl27", rpm:"lib64gnutls-ssl27~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-xssl0", rpm:"lib64gnutls-xssl0~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls28", rpm:"lib64gnutls28~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-ssl27", rpm:"libgnutls-ssl27~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-xssl0", rpm:"libgnutls-xssl0~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls28", rpm:"libgnutls28~3.2.21~1.4.mga5", rls:"MAGEIA5"))) {
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
