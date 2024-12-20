# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.14875.1");
  script_cve_id("CVE-2021-2163", "CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2432", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35586", "CVE-2021-35588", "CVE-2021-41035");
  script_tag(name:"creation_date", value:"2022-01-20 07:39:58 +0000 (Thu, 20 Jan 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 01:21:33 +0000 (Thu, 28 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:14875-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:14875-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-202214875-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2022:14875-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_1-ibm fixes the following issues:

Update to Java 7.1 Service Refresh 5 Fix Pack 0

CVE-2021-41035: before version 0.29.0, the openj9 JVM does not throw
 IllegalAccessError for MethodHandles that invoke inaccessible interface
 methods. (bsc#1194198, bsc#1192052)

CVE-2021-35586: Excessive memory allocation in BMPImageReader.
 (bsc#1191914)

CVE-2021-35564: Certificates with end dates too far in the future can
 corrupt keystore. (bsc#1191913)

CVE-2021-35559: Excessive memory allocation in RTFReader. (bsc#1191911)

CVE-2021-35556: Excessive memory allocation in RTFParser. (bsc#1191910)

CVE-2021-35565: Loop in HttpsServer triggered during TLS session close.
 (bsc#1191909)

CVE-2021-35588: Incomplete validation of inner class references in
 ClassFileParser. (bsc#1191905)

CVE-2021-2341: Fixed a flaw inside the FtpClient. (bsc#1188564)

CVE-2021-2369: JAR file handling problem containing multiple MANIFEST.MF
 files. (bsc#1188565)

CVE-2021-2432: Fixed a vulnerability in the omponent JNDI. (bsc#1188568)

CVE-2021-2163: Incomplete enforcement of JAR signing disabled
 algorithms. (bsc#1185055)");

  script_tag(name:"affected", value:"'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr5.0~26.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr5.0~26.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-devel", rpm:"java-1_7_1-ibm-devel~1.7.1_sr5.0~26.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr5.0~26.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr5.0~26.68.1", rls:"SLES11.0SP4"))) {
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
