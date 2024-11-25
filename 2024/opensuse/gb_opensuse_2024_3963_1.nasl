# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856716");
  script_version("2024-11-13T05:05:39+0000");
  script_cve_id("CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:12 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-11 08:47:51 +0000 (Mon, 11 Nov 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:3963-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3963-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YF4VNHR3FWXUMWTELTEOVDEWZ6SVMYHZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:3963-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openjdk fixes the following issues:

  * Update to upstream tag jdk-17.0.13+11 (October 2024 CPU)

  * Security fixes

  * JDK-8307383: Enhance DTLS connections

  * JDK-8290367, JDK-8332643: Update default value and extend the scope of com.sun.jndi.ldap.object.trustSerialData system property

  * JDK-8328286, CVE-2024-21208, bsc#1231702: Enhance HTTP client

  * JDK-8328544, CVE-2024-21210, bsc#1231711: Improve handling of vectorization

  * JDK-8328726: Better Kerberos support

  * JDK-8331446, CVE-2024-21217, bsc#1231716: Improve deserialization support

  * JDK-8332644, CVE-2024-21235, bsc#1231719: Improve graph optimizations

  * JDK-8335713: Enhance vectorization analysis

  * Other changes

  * JDK-7022325: TEST_BUG: test/java/util/zip/ZipFile/ /ReadLongZipFileName.java leaks files if it fails

  * JDK-7026262: HttpServer: improve handling of finished HTTP exchanges

  * JDK-7124313: [macosx] Swing Popups should overlap taskbar

  * JDK-8005885: enhance PrintCodeCache to print more data

  * JDK-8051959: Add thread and timestamp options to java.security.debug system property

  * JDK-8170817: G1: Returning MinTLABSize from unsafe_max_tlab_alloc causes TLAB flapping

  * JDK-8183227: read/write APIs in class os shall return ssize_t

  * JDK-8193547: Regression automated test '/open/test/jdk/java/ /awt/Toolkit/DesktopProperties/rfe4758438.java' fails

  * JDK-8222884: ConcurrentClassDescLookup.java times out intermittently

  * JDK-8233725: ProcessTools.startProcess() has output issues when using an OutputAnalyzer at the same time

  * JDK-8238169: BasicDirectoryModel getDirectories and DoChangeContents.run can deadlock

  * JDK-8241550: [macOS] SSLSocketImpl/ReuseAddr.java failed due to 'BindException: Address already in use'

  * JDK-8255898: Test java/awt/FileDialog/FilenameFilterTest/ /FilenameFilterTest.java fails on Mac OS

  * JDK-8256291: RunThese30M fails 'assert(_class_unload ? true : ((((JfrTraceIdBits::load(class_loader_klass)) & ((1    4)    8)) != 0))) failed: invariant'

  * JDK-8257540: javax/swing/JFileChooser/8041694/bug8041694.java failed with 'RuntimeException: The selected directory name is not the expected 'd ' but 'D '.'

  * JDK-8259866: two java.util tests failed with 'IOException: There is not enough space on the disk'

  * JDK-8260633: [macos] java/awt/dnd/MouseEventAfterStartDragTest/ /MouseEventAfterStartDragTest.html test failed

  * JDK-8261433: Better pkcs11 performance for libpkcs11:C_EncryptInit/libpkcs11 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless", rpm:"java-17-openjdk-headless~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel-debuginfo", rpm:"java-17-openjdk-devel-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debugsource", rpm:"java-17-openjdk-debugsource~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-jmods", rpm:"java-17-openjdk-jmods~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-src", rpm:"java-17-openjdk-src~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-devel", rpm:"java-17-openjdk-devel~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-debuginfo", rpm:"java-17-openjdk-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-headless-debuginfo", rpm:"java-17-openjdk-headless-debuginfo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-demo", rpm:"java-17-openjdk-demo~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk", rpm:"java-17-openjdk~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openjdk-javadoc", rpm:"java-17-openjdk-javadoc~17.0.13.0~150400.3.48.2", rls:"openSUSELeap15.5"))) {
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
