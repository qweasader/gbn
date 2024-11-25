# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2863.1");
  script_cve_id("CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"creation_date", value:"2024-08-12 04:24:46 +0000 (Mon, 12 Aug 2024)");
  script_version("2024-08-12T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-12 05:05:37 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:03 +0000 (Tue, 23 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2863-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2863-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242863-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2024:2863-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:
Update to 9.16.50:

Bug Fixes:
A regression in cache-cleaning code enabled memory use to grow
 significantly more quickly than before, until the configured
 max-cache-size limit was reached. This has been fixed.
Using rndc flush inadvertently caused cache cleaning to become
 less effective. This could ultimately lead to the configured
 max-cache-size limit being exceeded and has now been fixed.
The logic for cleaning up expired cached DNS records was
 tweaked to be more aggressive. This change helps with enforcing
 max-cache-ttl and max-ncache-ttl in a timely manner.
It was possible to trigger a use-after-free assertion when the
 overmem cache cleaning was initiated. This has been fixed.
 New Features:
Added RESOLVER.ARPA to the built in empty zones.
Security Fixes:
It is possible to craft excessively large numbers of resource
 record types for a given owner name, which has the effect of
 slowing down database processing. This has been addressed by
 adding a configurable limit to the number of records that can
 be stored per name and type in a cache or zone database. The
 default is 100, which can be tuned with the new
 max-types-per-name option. (CVE-2024-1737, bsc#1228256)
Validating DNS messages signed using the SIG(0) protocol (RFC
 2931) could cause excessive CPU load, leading to a
 denial-of-service condition. Support for SIG(0) message
 validation was removed from this version of named.
 (CVE-2024-1975, bsc#1228257)
When looking up the NS records of parent zones as part of
 looking up DS records, it was possible for named to trigger an
 assertion failure if serve-stale was enabled. This has been
 fixed. (CVE-2024-4076, bsc#1228258)");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.50~150400.5.43.1", rls:"SLES15.0SP4"))) {
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
