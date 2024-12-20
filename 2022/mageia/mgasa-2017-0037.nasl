# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0037");
  script_cve_id("CVE-2016-9772");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-08 18:46:04 +0000 (Wed, 08 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0037");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0037.html");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.18.1/RELNOTES-1.6.18.1");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.18.2/RELNOTES-1.6.18.2");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.6.18.3/RELNOTES-1.6.18.3");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/02/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19879");
  script_xref(name:"URL", value:"https://dl.openafs.org/dl/1.6.19/RELNOTES-1.6.19");
  script_xref(name:"URL", value:"https://dl.openafs.org/dl/1.6.20/RELNOTES-1.6.20");
  script_xref(name:"URL", value:"https://www.openafs.org/pages/security/OPENAFS-SA-2016-003.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openafs' package(s) announced via the MGASA-2017-0037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to incomplete initialization or clearing of reused memory, OpenAFS
directory objects are likely to contain 'dead' directory entry
information. This extraneous information is not active - that is, it is
logically invisible to the fileserver and client. However, the leaked
information is physically visible on the fileserver vice partition, on
the wire in FetchData replies and other RPCs, and on the client cache
partition. This constitutes a leak of directory information
(CVE-2016-9772).

The openafs package has been updated to version 1.6.20, to fix this
issue and other bugs.");

  script_tag(name:"affected", value:"'openafs' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-static-devel", rpm:"lib64openafs-static-devel~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-static-devel", rpm:"libopenafs-static-devel~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.6.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.6.20~1.mga5", rls:"MAGEIA5"))) {
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
