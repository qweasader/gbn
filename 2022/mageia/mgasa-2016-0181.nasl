# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0181");
  script_cve_id("CVE-2016-4574", "CVE-2016-4579");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-13 20:39:59 +0000 (Mon, 13 Jun 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0181)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0181");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0181.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/05/10/4");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/05/11/10");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18437");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libksba' package(s) announced via the MGASA-2016-0181 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libksba packages fix security vulnerabilities:

An out-of-bounds read access in _ksba_dn_to_str() in libksba 1.3.3, due to an
incomplete fix for CVE-2016-4356, could result in denial of service
(CVE-2016-4574).

In liksba 1.3.3, the returned length of the object from _ksba_ber_parse_tl()
(ti.length) was not always checked against the actual buffer length, thus
leading to a read access after the end of the buffer, which could result in
denial of service (CVE-2016-4579).");

  script_tag(name:"affected", value:"'libksba' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ksba-devel", rpm:"lib64ksba-devel~1.3.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ksba8", rpm:"lib64ksba8~1.3.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksba", rpm:"libksba~1.3.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksba-devel", rpm:"libksba-devel~1.3.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libksba8", rpm:"libksba8~1.3.4~1.mga5", rls:"MAGEIA5"))) {
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
