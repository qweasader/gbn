# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0310");
  script_cve_id("CVE-2020-14312");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-08 22:25:55 +0000 (Mon, 08 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0310");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0310.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26964");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1851342");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1852373");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the MGASA-2020-0310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dnsmasq package fix insecure default configuration potentially
making it an open resolver (CVE-2020-14312).

In its default configuration, dnsmasq listen and answer query from any
address even outside of the local subnet. Thus, it may inadvertently
become an open resolver which might be used in Distributed Denial of
Service attacks.

This update add the option --local-service at startup which limits
dnsmasq to listen only to machines on the same local network.

This option only works if there aren't any of the following options
on cmdline or in dnsmasq.conf (without the double dash):
--interface
--except-interface
--listen-address
--auth-server");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.80~5.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.80~5.3.mga7", rls:"MAGEIA7"))) {
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
