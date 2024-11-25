# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0104");
  script_cve_id("CVE-2018-13441", "CVE-2018-13457", "CVE-2018-13458", "CVE-2018-18245");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 15:16:00 +0000 (Thu, 06 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0104)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0104");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0104.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24290");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/3EGOZ3JA6TL3YUZ3XWYQ47OYQAJTWOTL/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios' package(s) announced via the MGASA-2019-0104 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Nagios Core version 4.4.1 and earlier. The qh_help
function is prone to a NULL pointer dereference vulnerability, which allows
attacker to cause a local denial-of-service condition by sending a crafted
payload to the listening UNIX socket (CVE-2018-13441).

A flaw was found in Nagios Core version 4.4.1 and earlier. The qh_echo
function is prone to a NULL pointer dereference vulnerability, which allows
attacker to cause a local denial-of-service condition by sending a crafted
payload to the listening UNIX socket (CVE-2018-13457).

A flaw was found in Nagios Core version 4.4.1 and earlier. The qh_core
function is prone to a NULL pointer dereference vulnerability, which allows
attacker to cause a local denial-of-service condition by sending a crafted
payload to the listening UNIX socket (CVE-2018-13458).

A cross-site scripting (XSS) vulnerability has been discovered in Nagios
Core. This vulnerability allows attackers to place malicious JavaScript
code into the web frontend through manipulation of plugin output. In order
to do this the attacker needs to be able to manipulate the output returned
by nagios checks, e.g. by replacing a plugin on one of the monitored
endpoints. Execution of the payload then requires that an authenticated
user creates an alert summary report which contains the corresponding
output (CVE-2018-18245).");

  script_tag(name:"affected", value:"'nagios' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"nagios", rpm:"nagios~4.3.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-devel", rpm:"nagios-devel~4.3.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-www", rpm:"nagios-www~4.3.1~2.2.mga6", rls:"MAGEIA6"))) {
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
