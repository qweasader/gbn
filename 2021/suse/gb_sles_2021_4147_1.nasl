# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.4147.1");
  script_cve_id("CVE-2020-14367");
  script_tag(name:"creation_date", value:"2021-12-23 03:29:23 +0000 (Thu, 23 Dec 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-02 14:05:14 +0000 (Wed, 02 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:4147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:4147-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20214147-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony' package(s) announced via the SUSE-SU-2021:4147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chrony fixes the following issues:

Chrony was updated to 4.1:

Add support for NTS servers specified by IP address (matching Subject
 Alternative Name in server certificate)

Add source-specific configuration of trusted certificates

Allow multiple files and directories with trusted certificates

Allow multiple pairs of server keys and certificates

Add copy option to server/pool directive

Increase PPS lock limit to 40% of pulse interval

Perform source selection immediately after loading dump files

Reload dump files for addresses negotiated by NTS-KE server

Update seccomp filter and add less restrictive level

Restart ongoing name resolution on online command

Fix dump files to not include uncorrected offset

Fix initstepslew to accept time from own NTP clients

Reset NTP address and port when no longer negotiated by NTS-KE server

Update clknetsim to snapshot f89702d.

Ensure the correct pool packages are installed for openSUSE and SLE
 (bsc#1180689).

Enable syscallfilter unconditionally (bsc#1181826).

Chrony was updated to 4.0:

Enhancements

Add support for Network Time Security (NTS) authentication

Add support for AES-CMAC keys (AES128, AES256) with Nettle

Add authselectmode directive to control selection of unauthenticated
 sources

Add binddevice, bindacqdevice, bindcmddevice directives

Add confdir directive to better support fragmented configuration

Add sourcedir directive and 'reload sources' command to support dynamic
 NTP sources specified in files

Add clockprecision directive

Add dscp directive to set Differentiated Services Code Point (DSCP)

Add -L option to limit log messages by severity

Add -p option to print whole configuration with included files

Add -U option to allow start under non-root user

Allow maxsamples to be set to 1 for faster update with -q/-Q
 option

Avoid replacing NTP sources with sources that have unreachable address

Improve pools to repeat name resolution to get 'maxsources' sources

Improve source selection with trusted sources

Improve NTP loop test to prevent synchronisation to itself

Repeat iburst when NTP source is switched from offline state to online

Update clock synchronisation status and leap status more frequently

Update seccomp filter

Add 'add pool' command

Add 'reset sources' command to drop all measurements

Add authdata command to print details about NTP authentication

Add selectdata command to print details about source selection

Add -N option and sourcename command to print original names
 of sources

Add -a option to some commands to print also unresolved sources

Add -k, -p, -r options to clients command to select, limit, reset data

Bug fixes

Don't set interface for NTP responses to allow asymmetric routing

Handle RTCs that don't support interrupts

Respond to command requests with correct address on multihomed hosts

Removed features

Drop support for RIPEMD keys (RMD128, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chrony' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~4.1~5.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~4.1~5.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debugsource", rpm:"chrony-debugsource~4.1~5.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~4.1~5.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~4.1~5.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debugsource", rpm:"chrony-debugsource~4.1~5.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~4.1~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~4.1~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debugsource", rpm:"chrony-debugsource~4.1~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~4.1~5.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~4.1~5.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debugsource", rpm:"chrony-debugsource~4.1~5.9.1", rls:"SLES12.0SP5"))) {
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
