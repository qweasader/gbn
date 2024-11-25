# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856350");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2024-21011", "CVE-2024-21012", "CVE-2024-21068", "CVE-2024-21085", "CVE-2024-21094");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:29 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:40 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:1498-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1498-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TES3WINTIBIEXGJTEO3T2IMOERMZHFMM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:1498-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

  * CVE-2024-21011: Fixed denial of service due to long Exception message
      logging (JDK-8319851,bsc#1222979)

  * CVE-2024-21012: Fixed unauthorized data modification due HTTP/2 client
      improper reverse DNS lookup (JDK-8315708,bsc#1222987)

  * CVE-2024-21068: Fixed integer overflow in C1 compiler address generation
      (JDK-8322122,bsc#1222983)

  * CVE-2024-21085: Fixed denial of service due to Pack200 excessive memory
      allocation (JDK-8322114,bsc#1222984)

  * CVE-2024-21094: Fixed unauthorized data modification due to C2 compilation
      failure with 'Exceeded _node_regs array'
      (JDK-8317507,JDK-8325348,bsc#1222986)

  Other fixes: \- Upgrade to upstream tag jdk-11.0.23+9 (April 2024 CPU) *
  Security fixes \+ JDK-8318340: Improve RSA key implementations * Other changes
  \+ JDK-6928542: Chinese characters in RTF are not decoded \+ JDK-7132796:
  [macosx] closed/javax/swing/JComboBox/4517214/ /bug4517214.java fails on MacOS
  \+ JDK-7148092: [macosx] When Alt+down arrow key is pressed, the combobox popup
  does not appear. \+ JDK-8054022: HttpURLConnection timeouts with Expect:
  100-Continue and no chunking \+ JDK-8054572: [macosx] JComboBox paints the
  border incorrectly \+ JDK-8058176: [mlvm] tests should not allow code cache
  exhaustion \+ JDK-8067651: LevelTransitionTest.java, fix trivial methods levels
  logic \+ JDK-8068225: nsk/jdi/EventQueue/remove_l/remove_l005 intermittently
  times out \+ JDK-8156889: ListKeychainStore.sh fails in some virtualized
  environments \+ JDK-8166275: vm/mlvm/meth/stress/compiler/deoptimize keeps
  timeouting \+ JDK-8166554: Avoid compilation blocking in
  OverloadCompileQueueTest.java \+ JDK-8169475: WheelModifier.java fails by
  timeout \+ JDK-8180266: Convert sun/security/provider/KeyStore/DKSTest.sh to
  Java Jtreg Test \+ JDK-8186610: move ModuleUtils to top-level testlibrary \+
  JDK-8192864: defmeth tests can hide failures \+ JDK-8193543: Regression
  automated test '/open/test/jdk/java/
  /awt/TrayIcon/SystemTrayInstance/SystemTrayInstanceTest.java' fails \+
  JDK-8198668: MemoryPoolMBean/isUsageThresholdExceeded/
  /isexceeded001/TestDescription.java still failing \+ JDK-8202282: [TESTBUG]
  appcds TestCommon .makeCommandLineForAppCDS() can be removed \+ JDK-8202790: DnD
  test DisposeFrameOnDragTest.java does not clean up \+ JDK-8202931: [macos]
  java/awt/Choice/ChoicePopupLocation/ /ChoicePopupLocation.java fails \+
  JDK-8207211: [TESTBUG] Remove excessive output from CDS/AppCDS tests \+
  JDK-8207214: Broken links in JDK API serialized-form ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel-debuginfo", rpm:"java-11-openjdk-devel-debuginfo~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless-debuginfo", rpm:"java-11-openjdk-headless-debuginfo~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.23.0~150000.3.113.1", rls:"openSUSELeap15.6"))) {
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