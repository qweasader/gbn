# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0816.1");
  script_cve_id("CVE-2022-21248", "CVE-2022-21277", "CVE-2022-21282", "CVE-2022-21283", "CVE-2022-21291", "CVE-2022-21293", "CVE-2022-21294", "CVE-2022-21296", "CVE-2022-21299", "CVE-2022-21305", "CVE-2022-21340", "CVE-2022-21341", "CVE-2022-21360", "CVE-2022-21365", "CVE-2022-21366");
  script_tag(name:"creation_date", value:"2022-03-14 15:12:02 +0000 (Mon, 14 Mar 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-25 13:56:27 +0000 (Tue, 25 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0816-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0816-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220816-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk' package(s) announced via the SUSE-SU-2022:0816-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

CVE-2022-21248: Fixed incomplete deserialization class filtering in
 ObjectInputStream. (bnc#1194926)

CVE-2022-21277: Fixed incorrect reading of TIFF files in
 TIFFNullDecompressor. (bnc#1194930)

CVE-2022-21282: Fixed Insufficient URI checks in the XSLT
 TransformerImpl. (bnc#1194933)

CVE-2022-21283: Fixed unexpected exception thrown in regex Pattern.
 (bnc#1194937)

CVE-2022-21291: Fixed Incorrect marking of writeable fields.
 (bnc#1194925)

CVE-2022-21293: Fixed Incomplete checks of StringBuffer and
 StringBuilder during deserialization. (bnc#1194935)

CVE-2022-21294: Fixed Incorrect IdentityHashMap size checks during
 deserialization. (bnc#1194934)

CVE-2022-21296: Fixed Incorrect access checks in XMLEntityManager.
 (bnc#1194932)

CVE-2022-21299: Fixed Infinite loop related to incorrect handling of
 newlines in XMLEntityScanner. (bnc#1194931)

CVE-2022-21305: Fixed Array indexing issues in LIRGenerator.
 (bnc#1194939)

CVE-2022-21340: Fixed Excessive resource use when reading JAR manifest
 attributes. (bnc#1194940)

CVE-2022-21341: Fixed OpenJDK: Insufficient checks when deserializing
 exceptions in ObjectInputStream. (bnc#1194941)

CVE-2022-21360: Fixed Excessive memory allocation in BMPImageReader.
 (bnc#1194929)

CVE-2022-21365: Fixed Integer overflow in BMPImageReader. (bnc#1194928)

CVE-2022-21366: Fixed Excessive memory allocation in TIFF*Decompressor.
 (bnc#1194927)");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Realtime Extension 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.14.0~3.74.2", rls:"SLES15.0SP3"))) {
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
