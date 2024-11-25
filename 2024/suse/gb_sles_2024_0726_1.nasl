# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0726.1");
  script_cve_id("CVE-2024-25710", "CVE-2024-26308");
  script_tag(name:"creation_date", value:"2024-03-01 04:23:12 +0000 (Fri, 01 Mar 2024)");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-22 15:21:36 +0000 (Thu, 22 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0726-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0726-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240726-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Java' package(s) announced via the SUSE-SU-2024:0726-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Java fixes the following issues:
apache-commons-codec was updated to version 1.16.1:


Changes in version 1.16.1:


New features:

Added Maven property project.build.outputTimestamp for build reproducibility



Bugs fixed:

Correct error in Base64 Javadoc Added minimum Java version in changes.xml Documentation update for the org.apache.commons.codec.digest.* package Precompile regular expression in UnixCrypt.crypt(byte[], String)
Fixed possible IndexOutOfBoundException in PhoneticEngine.encode method Fixed possible ArrayIndexOutOfBoundsException in QuotedPrintableCodec.encodeQuotedPrintable() method Fixed possible StringIndexOutOfBoundException in MatchRatingApproachEncoder.encode() method Fixed possible ArrayIndexOutOfBoundException in RefinedSoundex.getMappingCode()
Fixed possible IndexOutOfBoundsException in PercentCodec.insertAlwaysEncodeChars() method Deprecated UnixCrypt 0-argument constructor Deprecated Md5Crypt 0-argument constructor Deprecated Crypt 0-argument constructor Deprecated StringUtils 0-argument constructor Deprecated Resources 0-argument constructor Deprecated Charsets 0-argument constructor Deprecated CharEncoding 0-argument constructor



Changes in version 1.16.0:


Remove duplicated words from Javadocs

Use Standard Charset object Use String.contains() functions Avoid use toString() or substring() in favor of a simplified expression Fixed byte-skipping in Base16 decoding Fixed several typos, improve writing in some javadocs BaseNCodecOutputStream.eof() should not throw IOException.
Javadoc improvements and cleanups.
Deprecated BaseNCodec.isWhiteSpace(byte) and use Character.isWhitespace(int).
Added support for Blake3 family of hashes Added github/codeql-action Bump actions/cache from v2 to v3.0.10 Bump actions/setup-java from v1.4.1 to 3.5.1 Bump actions/checkout from 2.3.2 to 3.1.0 Bump commons-parent from 52 to 58 Bump junit from 4.13.1 to 5.9.1 Bump Java 7 to 8.
Bump japicmp-maven-plugin from 0.14.3 to 0.17.1.
Bump jacoco-maven-plugin from 0.8.5 to 0.8.8 (Fixes Java 15 builds).
Bump maven-surefire-plugin from 2.22.2 to 3.0.0-M7 Bump maven-javadoc-plugin from 3.2.0 to 3.4.1.
Bump animal-sniffer-maven-plugin from 1.19 to 1.22.
Bump maven-pmd-plugin from 3.13.0 to 3.19.0 Bump pmd from 6.47.0 to 6.52.0.
Bump maven-checkstyle-plugin from 2.17 to 3.2.0 Bump checkstyle from 8.45.1 to 9.3 Bump taglist-maven-plugin from 2.4 to 3.0.0 Bump jacoco-maven-plugin from 0.8.7 to 0.8.8.

apache-commons-compress was updated to version 1.26:


Changes in version 1.26:


Security issues fixed:

CVE-2024-26308: Fixed allocation of Resources Without Limits or Throttling vulnerability in
 Apache Commons Compress (bsc#1220068)
CVE-2024-25710: Fixed loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in
 Apache Commons Compress (bsc#1220070)



New Features:

Added and use ZipFile.builder(), ZipFile.Builder, and deprecate constructors ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Java' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-codec", rpm:"apache-commons-codec~1.16.1~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress", rpm:"apache-commons-compress~1.26.0~150200.3.16.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration2", rpm:"apache-commons-configuration2~2.9.0~150200.5.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-io", rpm:"apache-commons-io~2.15.1~150200.3.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gradle-local", rpm:"gradle-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ivy-local", rpm:"ivy-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.6~150200.4.21.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-logging-api", rpm:"maven-doxia-logging-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fml", rpm:"maven-doxia-module-fml~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fo", rpm:"maven-doxia-module-fo~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml", rpm:"maven-doxia-module-xhtml~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~1.11.1~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-jar-plugin", rpm:"maven-jar-plugin~3.3.0~150200.3.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.6.0~150200.4.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.6~150200.4.21.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-local", rpm:"maven-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~3.1.1~150200.3.7.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.18~150200.3.17.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resources-plugin", rpm:"maven-resources-plugin~3.3.1~150200.3.12.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-codec", rpm:"apache-commons-codec~1.16.1~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress", rpm:"apache-commons-compress~1.26.0~150200.3.16.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration2", rpm:"apache-commons-configuration2~2.9.0~150200.5.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-io", rpm:"apache-commons-io~2.15.1~150200.3.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gradle-local", rpm:"gradle-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ivy-local", rpm:"ivy-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven", rpm:"maven~3.9.6~150200.4.21.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-logging-api", rpm:"maven-doxia-logging-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fml", rpm:"maven-doxia-module-fml~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fo", rpm:"maven-doxia-module-fo~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml", rpm:"maven-doxia-module-xhtml~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~1.11.1~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-jar-plugin", rpm:"maven-jar-plugin~3.3.0~150200.3.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.6.0~150200.4.10.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-lib", rpm:"maven-lib~3.9.6~150200.4.21.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-local", rpm:"maven-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~3.1.1~150200.3.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-connector-basic", rpm:"maven-resolver-connector-basic~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-impl", rpm:"maven-resolver-impl~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-named-locks", rpm:"maven-resolver-named-locks~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-file", rpm:"maven-resolver-transport-file~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-http", rpm:"maven-resolver-transport-http~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-util", rpm:"maven-resolver-util~1.9.18~150200.3.17.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resources-plugin", rpm:"maven-resources-plugin~3.3.1~150200.3.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn", rpm:"xmvn~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-api", rpm:"xmvn-api~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-minimal", rpm:"xmvn-minimal~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-codec", rpm:"apache-commons-codec~1.16.1~150200.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-io", rpm:"apache-commons-io~2.15.1~150200.3.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-core", rpm:"maven-doxia-core~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-logging-api", rpm:"maven-doxia-logging-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-apt", rpm:"maven-doxia-module-apt~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-fo", rpm:"maven-doxia-module-fo~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xdoc", rpm:"maven-doxia-module-xdoc~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml", rpm:"maven-doxia-module-xhtml~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-module-xhtml5", rpm:"maven-doxia-module-xhtml5~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sink-api", rpm:"maven-doxia-sink-api~1.12.0~150200.4.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-doxia-sitetools", rpm:"maven-doxia-sitetools~1.11.1~150200.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-jar-plugin", rpm:"maven-jar-plugin~3.3.0~150200.3.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-javadoc-plugin", rpm:"maven-javadoc-plugin~3.6.0~150200.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-local", rpm:"maven-local~6.2.0~150200.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-reporting-api", rpm:"maven-reporting-api~3.1.1~150200.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-api", rpm:"maven-resolver-api~1.9.18~150200.3.17.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-spi", rpm:"maven-resolver-spi~1.9.18~150200.3.17.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maven-resolver-transport-wagon", rpm:"maven-resolver-transport-wagon~1.9.18~150200.3.17.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-connector", rpm:"xmvn-connector~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-core", rpm:"xmvn-core~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-install", rpm:"xmvn-install~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-mojo", rpm:"xmvn-mojo~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-resolve", rpm:"xmvn-resolve~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmvn-subst", rpm:"xmvn-subst~4.2.0~150200.3.18.1", rls:"SLES15.0SP4"))) {
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
