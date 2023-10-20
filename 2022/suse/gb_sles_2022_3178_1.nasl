# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3178.1");
  script_cve_id("CVE-2021-20178", "CVE-2021-20180", "CVE-2021-20191", "CVE-2021-20228", "CVE-2021-3447", "CVE-2021-3583", "CVE-2021-3620");
  script_tag(name:"creation_date", value:"2022-09-09 04:51:43 +0000 (Fri, 09 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-03 20:43:00 +0000 (Mon, 03 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3178-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223178-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Important for SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2022:3178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

ansible:

Update to version 2.9.27 (jsc#SLE-23631, jsc#SLE-24133)
 * CVE-2021-3620 ansible-connection module discloses sensitive info in
 traceback error message (in 2.9.27) (bsc#1187725)
 * CVE-2021-3583 Template Injection through yaml multi-line strings with
 ansible facts used in template. (in 2.9.23) (bsc#1188061)
 * ansible module nmcli is broken in ansible 2.9.13 (in 2.9.15)
 (bsc#1176460)

Update to 2.9.22:
 * CVE-2021-3447 (bsc#1183684) multiple modules expose secured values
 * CVE-2021-20228 (bsc#1181935) basic.py no_log with fallback option
 * CVE-2021-20191 (bsc#1181119) multiple collections exposes secured
 values
 * CVE-2021-20180 (bsc#1180942) bitbucket_pipeline_variable exposes
 sensitive values
 * CVE-2021-20178 (bsc#1180816) user data leak in snmp_facts module

dracut-saltboot:

Require e2fsprogs (bsc#1202614)

Update to version 0.1.1657643023.0d694ce
 * Update dracut-saltboot dependencies (bsc#1200970)
 * Fix network loading when ipappend is used in pxe config
 * Add new information messages

golang-github-QubitProducts-exporter_exporter:

Remove license file from %doc

mgr-daemon:

Version 4.3.5-1
 * Update translation strings

mgr-virtualization:

Version 4.3.6-1
 * Report all VMs in poller, not only running ones (bsc#1199528)

prometheus-blackbox_exporter:

Exclude s390 arch

python-hwdata:

Declare the LICENSE file as license and not doc

spacecmd:

Version 4.3.14-1
 * Fix missing argument on system_listmigrationtargets (bsc#1201003)
 * Show correct help on calling kickstart_importjson with no arguments
 * Fix tracebacks on spacecmd kickstart_export (bsc#1200591)
 * Change proxy container config default filename to end with tar.gz
 * Update translation strings

spacewalk-client-tools:

Version 4.3.11-1
 * Update translation strings

uyuni-common-libs:

Version 4.3.5-1
 * Fix reposync issue about 'rpm.hdr' object has no attribute 'get'

uyuni-proxy-systemd-services:

Version 4.3.6-1
 * Expose port 80 (bsc#1200142)
 * Use volumes rather than bind mounts
 * TFTPD to listen on udp port (bsc#1200968)
 * Add TAG variable in configuration
 * Fix containers namespaces in configuration

zypp-plugin-spacewalk:

1.0.13
 * Log in before listing channels. (bsc#1197963, bsc#1193585)");

  script_tag(name:"affected", value:"'Important for SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.1, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.2, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.3, SUSE Linux Enterprise Module for SUSE Manager Server 4.1, SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module for SUSE Manager Server 4.3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15, SUSE Manager Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~1.3.0~150000.3.15.1", rls:"SLES15.0"))) {
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
