# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0414");
  script_cve_id("CVE-2021-46848");
  script_tag(name:"creation_date", value:"2022-11-09 04:29:05 +0000 (Wed, 09 Nov 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 17:00:00 +0000 (Mon, 24 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0414");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0414.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31039");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012715.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UOQWW4AUK2TNVOVQ3OANN2IEBVJFBHJ4/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5707-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1' package(s) announced via the MGASA-2022-0414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU Libtasn1 before 4.19.0 has an ETYPE_OK off-by-one array size check
that affects asn1_encode_simple_der. (CVE-2021-46848)");

  script_tag(name:"affected", value:"'libtasn1' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tasn1-devel", rpm:"lib64tasn1-devel~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tasn1_6", rpm:"lib64tasn1_6~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-devel", rpm:"libtasn1-devel~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-tools", rpm:"libtasn1-tools~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1_6", rpm:"libtasn1_6~4.16.0~4.1.mga8", rls:"MAGEIA8"))) {
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
