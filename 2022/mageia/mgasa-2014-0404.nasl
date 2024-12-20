# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0404");
  script_cve_id("CVE-2014-2905", "CVE-2014-2906", "CVE-2014-2914", "CVE-2014-3856");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-04 17:09:46 +0000 (Tue, 04 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0404)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0404");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0404.html");
  script_xref(name:"URL", value:"http://fishshell.com/release_notes.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/09/28/8");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13984");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132618.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fish' package(s) announced via the MGASA-2014-0404 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated fish packages fix security vulnerability:

fish, from at least version 1.16.0 to version 2.1.0 (inclusive), does not
check the credentials of processes communicating over the fishd universal
variable server UNIX domain socket. This allows a local attacker to
elevate their privileges to those of a target user running fish, including
root (CVE-2014-2905).

fish, from at least version 1.16.0 to version 2.1.0 (inclusive), creates
temporary files in an insecure manner.

Versions 1.23.0 to 2.1.0 (inclusive) execute code via `funced` from these
temporary files, allowing privilege escalation to those of any user
running fish, including root (CVE-2014-3856).

Additionally, from at least version 1.16.0 to version 2.1.0 (inclusive),
fish will read data using the psub function from these temporary files,
meaning that the input of commands used with the psub function is under
the control of the attacker (CVE-2014-2906).

fish, from version 2.0.0 to version 2.1.0 (inclusive), fails to restrict
connections to the Web-based configuration service (fish_config). This
allows remote attackers to execute arbitrary code in the context of the
user running fish_config (CVE-2014-2914).

The service is generally only running for short periods of time. The use of
the fish_config tool is optional as other interfaces to fish configuration
are available.

The fish package has been updated to version 2.1.1 to fix these issues.");

  script_tag(name:"affected", value:"'fish' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"fish", rpm:"fish~2.1.1~1.mga4", rls:"MAGEIA4"))) {
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
